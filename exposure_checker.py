#!/usr/bin/env python3
"""
Exposure Checker - scan a machine YOU OWN for risky open ports and weak config.

USAGE:
    # Port scan (default)
    python exposure_checker.py                          # scan your own machine (127.0.0.1)
    python exposure_checker.py 192.168.1.50             # scan a LAN host you own

    # Local config / file-system checks (some need sudo for full coverage)
    python exposure_checker.py --ssh-audit              # audit /etc/ssh/sshd_config
    python exposure_checker.py --ssh-audit-only         # skip port scan; SSH audit only
    python exposure_checker.py --check-firewall         # is a firewall active?
    python exposure_checker.py --check-listeners        # services bound to 0.0.0.0
    python exposure_checker.py --check-world-writable   # world-writable files in key dirs
    python exposure_checker.py --check-suid             # SUID/SGID binaries in standard paths
    python exposure_checker.py --check-cron             # cron jobs with world-writable scripts
    python exposure_checker.py --full-audit             # all local checks on the target

    # Remote / tool-dependent checks
    python exposure_checker.py --tls-check example.com       # TLS cert expiry (port 443)
    python exposure_checker.py --tls-check example.com:8443  # custom port
    python exposure_checker.py --trivy-scan                  # CVE-scan all local Docker images
    python exposure_checker.py --trivy-scan nginx:latest     # CVE-scan one image

    # Output / CI
    python exposure_checker.py [FLAGS] --json               # emit JSON to stdout
    python exposure_checker.py [FLAGS] --output report.json # save JSON report to file
    python exposure_checker.py [FLAGS] --fail-on high       # exit 1 if any HIGH+ finding

WARNING: Only scan systems you own or have WRITTEN permission to test.
         Scanning machines you don't control is illegal in most places.
"""

import argparse
import concurrent.futures
import datetime
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import time
import platform

# cryptography is required for TLS cert expiry checks (pip install cryptography)
try:
    from cryptography import x509 as _cx509
    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False


_OS = platform.system()  # "Linux" | "Darwin" | "Windows"

# On Windows, every subprocess launched from a windowed (no-console) app
# flashes a console window unless CREATE_NO_WINDOW is set.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if platform.system() == "Windows" else 0


def _ps(cmd: str, timeout: int = 30) -> tuple:
    """Run a PowerShell command. Returns (stdout_str, returncode).

    - CREATE_NO_WINDOW: prevents a console flash in the windowed app.
    - errors="replace": PowerShell on non-English Windows emits OEM-codepage
      bytes that crash text=True decoding with UnicodeDecodeError.
    """
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
    """Return the argv prefix that re-launches *this* program for cron /
    launchd / Task Scheduler entries.

    Critical for the frozen (PyInstaller) app: ``__file__`` lives inside the
    one-file bundle's temp ``_MEIPASS`` directory, which is deleted when the
    app exits — baking it into a schedule produces entries that silently
    break. Frozen builds must be re-launched via ``sys.executable`` alone.
    """
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, os.path.abspath(__file__)]


# ── Risk database ──────────────────────────────────────────────────────────────

# port -> (service, severity, why it matters, how to fix)
__version__ = "1.0.6"

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

# Ports that are 'take a closer look' rather than inherently bad
SPECIAL = {
    22:  ("SSH", "REVIEW", "SSH is fine IF it's key-only. Password auth invites brute-forcing.",
          "Set 'PasswordAuthentication no', use keys, consider fail2ban."),
    443: ("HTTPS", "INFO",
          "Encrypted web service - good. Just confirm it isn't an exposed admin panel.",
          "Keep TLS current; protect any admin UI behind auth."),
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "REVIEW": 3, "INFO": 4}

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


# ── Output / JSON reporter ─────────────────────────────────────────────────────

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
        """Print the closing separator for a check section."""
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
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(_render_html(self._data))
            else:
                with open(path, "w") as fh:
                    json.dump(self._data, fh, indent=2, default=str)
            return None
        except OSError as e:
            return str(e)

    def findings_at_or_above(self, severity):
        """Return all findings whose severity is at or above *severity*."""
        threshold = SEVERITY_ORDER.get(severity.upper(), 9)
        return [
            f
            for check in self._data["checks"]
            for f in check.get("findings", [])
            if SEVERITY_ORDER.get(f.get("severity", ""), 9) <= threshold
        ]


# ── SSH config audit ───────────────────────────────────────────────────────────

_SSHD_CONFIG = "/etc/ssh/sshd_config"
_SSHD_CONFIG_WINDOWS = r"C:\ProgramData\ssh\sshd_config"

# (lowercase_key, bad_value_set, severity, display_label, why, fix, insecure_default)
# insecure_default: effective value when the key is absent; None = skip if absent.
_SSH_RULES = [
    # PasswordAuthentication defaults to yes in most OpenSSH packages.
    ("passwordauthentication", {"yes"}, "HIGH",
     "PasswordAuthentication yes",
     "Password login is enabled — SSH is a prime brute-force target.",
     "Set 'PasswordAuthentication no'; use SSH key pairs only.",
     "yes"),
    ("permitemptypasswords", {"yes"}, "CRITICAL",
     "PermitEmptyPasswords yes",
     "Accounts with empty passwords can authenticate over SSH.",
     "Set 'PermitEmptyPasswords no' immediately.",
     None),
    ("permitrootlogin", {"yes"}, "CRITICAL",
     "PermitRootLogin yes",
     "Root can log in directly over SSH — one stolen session = full machine control.",
     "Set 'PermitRootLogin no'; log in as a regular user and sudo.",
     None),
    ("permitrootlogin", {"without-password", "prohibit-password"}, "HIGH",
     "PermitRootLogin without-password / prohibit-password",
     "Root can still log in with an SSH key; any compromised authorized key = root access.",
     "Set 'PermitRootLogin no' to fully block direct root SSH access.",
     None),
    ("hostbasedauthentication", {"yes"}, "HIGH",
     "HostbasedAuthentication yes",
     "Host-based auth trusts the calling machine, not per-user keys — easy to spoof.",
     "Set 'HostbasedAuthentication no'.",
     None),
    ("strictmodes", {"no"}, "HIGH",
     "StrictModes no",
     "StrictModes off lets SSH accept world-writable authorized_keys files.",
     "Set 'StrictModes yes' (the OpenSSH default).",
     None),
    ("x11forwarding", {"yes"}, "MEDIUM",
     "X11Forwarding yes",
     "X11 forwarding can be abused to capture keystrokes or inject commands on the server.",
     "Set 'X11Forwarding no' unless you specifically need remote GUI apps.",
     None),
    ("allowagentforwarding", {"yes"}, "MEDIUM",
     "AllowAgentForwarding yes",
     "Agent forwarding lets a compromised server pivot to other systems using your local SSH keys.",
     "Set 'AllowAgentForwarding no' unless explicitly required.",
     None),
    ("permituserenvironment", {"yes"}, "MEDIUM",
     "PermitUserEnvironment yes",
     "Users can inject environment variables that may override PATH or bypass access controls.",
     "Set 'PermitUserEnvironment no'.",
     None),
    ("protocol", {"1"}, "CRITICAL",
     "Protocol 1",
     "SSH protocol v1 is cryptographically broken.",
     "Remove the 'Protocol' line; modern OpenSSH uses v2 only.",
     None),
]

_MAX_AUTH_TRIES_THRESHOLD = 6
_LOGIN_GRACE_TIME_THRESHOLD = 60  # seconds

# Map lowercase sshd key → (ProperDirectiveName, correct_value)
# value=None → remove the directive (legacy / deprecated)
_SSH_FIX_MAP = {
    "passwordauthentication":  ("PasswordAuthentication",  "no"),
    "permitemptypasswords":    ("PermitEmptyPasswords",    "no"),
    "permitrootlogin":         ("PermitRootLogin",         "no"),
    "hostbasedauthentication": ("HostbasedAuthentication", "no"),
    "strictmodes":             ("StrictModes",             "yes"),
    "x11forwarding":           ("X11Forwarding",           "no"),
    "allowagentforwarding":    ("AllowAgentForwarding",    "no"),
    "permituserenvironment":   ("PermitUserEnvironment",   "no"),
    "maxauthtries":            ("MaxAuthTries",            "3"),
    "logingracetime":          ("LoginGraceTime",          "60"),
    "protocol":                ("Protocol",               None),
}

_SSHD_RELOAD = (
    "systemctl reload-or-restart ssh 2>/dev/null "
    "|| systemctl reload-or-restart sshd 2>/dev/null || true"
)


def _sshd_fix(directive, value):
    """Fix commands: set or add a directive in /etc/ssh/sshd_config and reload."""
    cfg = "/etc/ssh/sshd_config"
    pat = f"^[[:space:]]*#*[[:space:]]*{directive}[[:space:]]"
    replacement = f"{directive} {value}"
    return [
        (
            f"( grep -qE '{pat}' {cfg} "
            f"&& sed -i 's|{pat}.*|{replacement}|' {cfg} ) "
            f"|| printf '\\n{replacement}\\n' >> {cfg}"
        ),
        _SSHD_RELOAD,
    ]


def _sshd_remove(directive):
    """Fix commands: remove a deprecated directive from /etc/ssh/sshd_config."""
    cfg = "/etc/ssh/sshd_config"
    return [
        f"sed -i '/^[[:space:]]*#*[[:space:]]*{directive}[[:space:]]/d' {cfg}",
        _SSHD_RELOAD,
    ]


def _sshd_fix_windows(directive, value):
    """PowerShell fix commands: set or add a directive in sshd_config on Windows."""
    cfg = _SSHD_CONFIG_WINDOWS
    pat = f"(?im)^#?\\s*{re.escape(directive)}\\s+.*"
    return [
        f"(Get-Content '{cfg}') -replace '{pat}', '{directive} {value}' | Set-Content '{cfg}'",
        "Restart-Service sshd -ErrorAction SilentlyContinue",
    ]


def _sshd_remove_windows(directive):
    """PowerShell fix commands: remove a directive from sshd_config on Windows."""
    cfg = _SSHD_CONFIG_WINDOWS
    pat = f"(?im)^\\s*{re.escape(directive)}\\s"
    return [
        f"(Get-Content '{cfg}') | Where-Object {{ $_ -notmatch '{pat}' }} | Set-Content '{cfg}'",
        "Restart-Service sshd -ErrorAction SilentlyContinue",
    ]


def _parse_sshd_config(path):
    """Return ({lowercase_key: lowercase_value}, error_or_None).
    First occurrence wins (matches OpenSSH precedence). Include directives ignored.
    """
    settings = {}
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) != 2:
                    continue
                key = parts[0].lower()
                if key not in settings:
                    settings[key] = parts[1].strip().lower()
    except PermissionError:
        return None, "permission denied reading sshd_config — re-run with sudo"
    except FileNotFoundError:
        return None, f"sshd_config not found at {path}"
    except OSError as e:
        return None, f"could not read sshd_config: {e}"
    return settings, None


def _parse_grace_time(raw):
    """Parse a LoginGraceTime value to seconds; return None on parse error."""
    try:
        if raw.endswith("m"):
            return int(raw[:-1]) * 60
        if raw.endswith("h"):
            return int(raw[:-1]) * 3600
        return int(raw)
    except (ValueError, AttributeError):
        return None


def audit_ssh(reporter, path=None):
    if path is None:
        path = _SSHD_CONFIG_WINDOWS if _OS == "Windows" else _SSHD_CONFIG
    reporter.begin("SSH CONFIG AUDIT", f"File : {path}")

    settings, err = _parse_sshd_config(path)
    if err:
        reporter.error(f"SSH audit skipped: {err}")
        return

    pending = []  # [(severity, label, why, fix, extra_kwargs, ssh_key)]

    for key, bad_vals, severity, label, why, fix, default in _SSH_RULES:
        actual = settings.get(key, default)
        if actual is not None and actual in bad_vals:
            pending.append((severity, label, why, fix, {}, key))

    raw = settings.get("maxauthtries")
    if raw is not None:
        try:
            val = int(raw)
            if val > _MAX_AUTH_TRIES_THRESHOLD:
                pending.append((
                    "MEDIUM", f"MaxAuthTries {val}",
                    f"MaxAuthTries {val} allows many guesses per connection, aiding brute force.",
                    "Set 'MaxAuthTries 3' or lower.",
                    {}, "maxauthtries",
                ))
        except ValueError:
            pass

    raw = settings.get("logingracetime")
    if raw is not None:
        secs = _parse_grace_time(raw)
        if secs is not None and secs > _LOGIN_GRACE_TIME_THRESHOLD:
            pending.append((
                "MEDIUM", f"LoginGraceTime {raw}",
                f"LoginGraceTime {raw} lets unauthenticated connections hold slots open longer.",
                f"Set 'LoginGraceTime {_LOGIN_GRACE_TIME_THRESHOLD}' or lower.",
                {}, "logingracetime",
            ))

    if not pending:
        reporter.ok("No SSH config issues found")
        return

    pending.sort(key=lambda f: SEVERITY_ORDER.get(f[0], 9))
    if not reporter.json_mode:
        print(f"\n[!] {len(pending)} SSH config issue(s):")
    for severity, label, why, fix, extra, ssh_key in pending:
        fix_info = _SSH_FIX_MAP.get(ssh_key)
        if fix_info:
            name, value = fix_info
            if _OS == "Windows":
                fix_cmds = _sshd_remove_windows(name) if value is None else _sshd_fix_windows(name, value)
            else:
                fix_cmds = _sshd_remove(name) if value is None else _sshd_fix(name, value)
        else:
            fix_cmds = None
        reporter.finding(severity, label, why, fix, fix_cmds=fix_cmds, **extra)

    crit = sum(1 for f in pending if f[0] == "CRITICAL")
    high = sum(1 for f in pending if f[0] == "HIGH")
    reporter.end(f"{crit} critical, {high} high-severity SSH issues. Review above.")


# ── TLS certificate expiry check ──────────────────────────────────────────────

_TLS_WARN_DAYS = 30
_TLS_CRITICAL_DAYS = 7


def _parse_tls_target(raw):
    """Parse 'host', 'host:port', or 'https://host[:port]' → (host, port, error_or_None)."""
    raw = raw.strip()
    for prefix in ("https://", "http://"):
        if raw.lower().startswith(prefix):
            raw = raw[len(prefix):]
    raw = raw.split("/")[0].split("?")[0].split("#")[0]

    if raw.startswith("["):
        end = raw.find("]")
        if end == -1:
            return None, None, "malformed IPv6 bracket address"
        host = raw[1:end]
        rest = raw[end + 1:]
        port_str = rest.lstrip(":") if rest.startswith(":") else "443"
    elif raw.count(":") > 1:
        host, port_str = raw, "443"
    else:
        colon = raw.rfind(":")
        host, port_str = (raw[:colon], raw[colon + 1:]) if colon != -1 else (raw, "443")

    try:
        port = int(port_str)
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        return None, None, f"invalid port '{port_str}'"

    if not host:
        return None, None, "host cannot be empty"

    try:
        socket.getaddrinfo(host, port)
    except socket.gaierror:
        return None, None, f"could not resolve '{host}'"

    return host, port, None


def check_tls(reporter, raw_target):
    if not _CRYPTO_OK:
        reporter.begin("TLS CERTIFICATE CHECK")
        reporter.error("requires 'cryptography' package — run: pip install cryptography")
        return

    host, port, err = _parse_tls_target(raw_target)
    subtitle = f"Target : {host}:{port}" if not err else None
    reporter.begin("TLS CERTIFICATE CHECK", subtitle)
    if err:
        reporter.error(f"TLS check skipped: {err}")
        return

    # CERT_NONE so we always retrieve the cert, even for expired/self-signed ones.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
    except ssl.SSLError as e:
        reporter.error(f"TLS error connecting to {host}:{port} — {e.reason}")
        return
    except OSError as e:
        reporter.error(f"Could not connect to {host}:{port} — {e}")
        return

    if not der:
        reporter.error(f"{host}:{port} sent no certificate")
        return

    try:
        cert = _cx509.load_der_x509_certificate(der)
        try:
            expiry = cert.not_valid_after_utc           # cryptography >= 42
        except AttributeError:
            expiry = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    except Exception:
        reporter.error(f"Could not parse certificate from {host}:{port}")
        return

    now = datetime.datetime.now(datetime.timezone.utc)
    days = (expiry - now).days
    expiry_fmt = expiry.strftime("%Y-%m-%d")

    if days < 0:
        severity = "CRITICAL"
        status = f"EXPIRED {abs(days)} day(s) ago (expired {expiry_fmt})"
        why = "An expired certificate causes hard HTTPS failures for every client — not a warning."
    elif days < _TLS_CRITICAL_DAYS:
        severity = "CRITICAL"
        status = f"expires in {days} day(s) — {expiry_fmt}"
        why = f"Only {days} day(s) until expiry; renewal must complete before {expiry_fmt}."
    elif days < _TLS_WARN_DAYS:
        severity = "HIGH"
        status = f"expires in {days} day(s) — {expiry_fmt}"
        why = f"Certificate expires {expiry_fmt} — renewals can fail; start the process now."
    else:
        severity = None
        status = f"expires in {days} day(s) — {expiry_fmt}"

    if severity is None:
        reporter.ok(f"{host}:{port} — certificate OK, {status}")
    else:
        reporter.finding(
            severity,
            f"{host}:{port} — {status}",
            why,
            "Renew the certificate now; automate renewals with Let's Encrypt / certbot.",
            days_remaining=days,
            expiry=expiry_fmt,
        )
    reporter.end()


# ── Docker image CVE scan (Trivy) ─────────────────────────────────────────────

_IMAGE_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._/:\-@]*$')
_IMAGE_MAX_LEN = 512

_TRIVY_INSTALL = """\
    Linux:  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
    macOS:  brew install trivy
    Docs:   https://aquasecurity.github.io/trivy/latest/getting-started/installation/"""


def _validate_image_name(name):
    return bool(name and len(name) <= _IMAGE_MAX_LEN and _IMAGE_RE.match(name))


def _trivy_scan_one(reporter, trivy_path, image):
    if not reporter.json_mode:
        print(f"  Scanning {image} ...")
    try:
        proc = subprocess.run(
            [trivy_path, "image", "--format", "json", "--quiet", image],
            capture_output=True, text=True, timeout=300,
        )
    except subprocess.TimeoutExpired:
        reporter.error(f"Scan of {image} timed out (>5 min)")
        return
    except OSError as e:
        reporter.error(f"Could not run trivy: {e}")
        return

    if not proc.stdout.strip():
        hint = (proc.stderr.strip().splitlines() or ["no output"])[0]
        reporter.error(f"trivy returned no JSON for {image}: {hint}")
        return

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        reporter.error(f"Could not parse trivy JSON for {image}")
        return

    by_sev = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "UNKNOWN": []}
    for block in data.get("Results") or []:
        for vuln in block.get("Vulnerabilities") or []:
            bucket = vuln.get("Severity", "UNKNOWN").upper()
            by_sev.setdefault(bucket, []).append(vuln)

    total = sum(len(v) for v in by_sev.values())
    if total == 0:
        if not reporter.json_mode:
            print(f"  [+] {image} — no CVEs found.\n")
        return

    overall = next(s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN") if by_sev[s])
    counts = "  ".join(
        f"{s.lower()}: {len(by_sev[s])}"
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
        if by_sev[s]
    )
    crits = by_sev["CRITICAL"]
    crit_list = [
        {"id": v.get("VulnerabilityID", "?"),
         "package": v.get("PkgName", "?"),
         "installed": v.get("InstalledVersion", "?"),
         "fixed": v.get("FixedVersion") or "no fix yet"}
        for v in crits[:10]
    ]

    reporter.finding(
        overall,
        f"{image} — {total} CVE(s): {counts}",
        f"{len(crits)} critical CVE(s) require immediate attention." if crits
        else f"{total} CVE(s) found across all severity levels.",
        "Update or rebuild the image with a patched base; re-run trivy to verify.",
        image=image,
        total_cves=total,
        by_severity={s: len(by_sev[s]) for s in by_sev},
        critical_cves=crit_list,
    )

    if crits and not reporter.json_mode:
        print(f"      critical CVEs:")
        for v in crits[:10]:
            vid = v.get("VulnerabilityID", "?")
            pkg = v.get("PkgName", "?")
            inst = v.get("InstalledVersion", "?")
            fixed = v.get("FixedVersion") or "no fix yet"
            print(f"        {vid}  {pkg} {inst}  (fix: {fixed})")
        if len(crits) > 10:
            print(f"        ... and {len(crits) - 10} more critical CVE(s)")


def scan_trivy(reporter, image_spec=None):
    """image_spec=None/'ALL': scan all local images; else scan that specific image."""
    trivy = shutil.which("trivy")
    reporter.begin("DOCKER IMAGE CVE SCAN (Trivy)")

    if not trivy:
        reporter.error("Trivy is not installed — cannot run CVE scan")
        if not reporter.json_mode:
            print("    Install Trivy:")
            print(_TRIVY_INSTALL)
        return

    if image_spec and image_spec not in ("ALL", ""):
        if not _validate_image_name(image_spec):
            reporter.error(f"Invalid image name '{image_spec}'")
            return
        images = [image_spec]
    else:
        docker = shutil.which("docker")
        if not docker:
            reporter.error(
                "Docker CLI not found — cannot list local images; "
                "pass a specific image: --trivy-scan IMAGE:TAG"
            )
            return
        try:
            ls = subprocess.run(
                [docker, "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"],
                capture_output=True, text=True, timeout=15,
            )
        except subprocess.TimeoutExpired:
            reporter.error("'docker image ls' timed out")
            return
        except OSError as e:
            reporter.error(f"Could not run docker: {e}")
            return

        if ls.returncode != 0:
            hint = (ls.stderr.strip().splitlines() or ["unknown error"])[0]
            reporter.error(f"'docker image ls' failed: {hint}")
            return

        images = [
            ln.strip() for ln in ls.stdout.splitlines()
            if ln.strip() and "<none>" not in ln and _validate_image_name(ln.strip())
        ]
        if not images:
            reporter.ok("No local Docker images found")
            return

        reporter.info(f"Found {len(images)} local image(s) to scan...")
        if not reporter.json_mode:
            print()

    for image in images:
        _trivy_scan_one(reporter, trivy, image)

    reporter.end()


# ── Firewall status check ─────────────────────────────────────────────────────

def _check_firewall_macos(reporter):
    reporter.begin("FIREWALL STATUS")
    # 1. Preference file — readable without root, unlike pfctl.
    #    globalstate: 0 = off, 1 = on, 2 = on (block all incoming)
    try:
        r = subprocess.run(
            ["defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"],
            capture_output=True, text=True, timeout=10,
        )
        state = r.stdout.strip()
        if r.returncode == 0 and state in ("1", "2"):
            reporter.ok("Application firewall is enabled"
                        + (" (block all incoming)" if state == "2" else ""))
            reporter.end()
            return
    except (OSError, subprocess.TimeoutExpired):
        pass
    # 2. socketfilterfw (may require privileges on newer macOS)
    sff = shutil.which("socketfilterfw") or "/usr/libexec/ApplicationFirewall/socketfilterfw"
    try:
        r = subprocess.run([sff, "--getglobalstate"], capture_output=True, text=True, timeout=10)
        if "enabled" in r.stdout.lower():
            reporter.ok("Application firewall is enabled")
            reporter.end()
            return
    except (OSError, subprocess.TimeoutExpired):
        pass
    # 3. pf (packet filter) — pfctl exits non-zero / prints nothing for
    #    non-root users, so only trust a positive answer.
    try:
        r = subprocess.run(["pfctl", "-s", "info"], capture_output=True, text=True, timeout=10)
        if "enabled" in r.stdout.lower():
            reporter.ok("pf firewall is enabled")
            reporter.end()
            return
    except (OSError, subprocess.TimeoutExpired):
        pass
    reporter.finding(
        "HIGH", "No active firewall detected",
        "Neither the application firewall nor pf appears to be running.",
        "Enable via: System Settings → Network → Firewall, or: sudo pfctl -e",
        fix_cmds=["sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"],
    )
    reporter.end("1 firewall issue.")


def _check_firewall_windows(reporter):
    reporter.begin("FIREWALL STATUS")
    out, rc = _ps("Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json")
    if rc != 0 or not out.strip():
        reporter.error("Could not query Windows Firewall (requires PowerShell)")
        reporter.end()
        return
    try:
        profiles = json.loads(out)
        if isinstance(profiles, dict):
            profiles = [profiles]
        all_off = all(not p.get("Enabled", False) for p in profiles)
        any_off = any(not p.get("Enabled", False) for p in profiles)
        if all_off:
            reporter.finding(
                "HIGH", "Windows Firewall disabled on all profiles",
                "All firewall profiles (Domain, Private, Public) are off.",
                "Enable via: Windows Security → Firewall & network protection",
                fix_cmds=["Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True"],
            )
            reporter.end("1 firewall issue.")
        elif any_off:
            off = [p["Name"] for p in profiles if not p.get("Enabled", False)]
            reporter.finding(
                "MEDIUM", f"Windows Firewall off for: {', '.join(off)}",
                "Some network profiles have the firewall disabled.",
                "Enable all profiles in Windows Security → Firewall & network protection",
                fix_cmds=[f"Set-NetFirewallProfile -Profile {','.join(off)} -Enabled True"],
            )
            reporter.end("1 firewall issue.")
        else:
            reporter.ok("Windows Firewall is enabled on all profiles")
            reporter.end()
    except (json.JSONDecodeError, KeyError):
        reporter.error("Could not parse firewall profile output")
        reporter.end()


def _ufw_enable_cmds(ufw_bin=None):
    """Return a safe sequence to enable ufw without locking out SSH.
    Uses full binary path because pkexec runs with a stripped PATH."""
    ufw = ufw_bin or shutil.which("ufw") or "/usr/sbin/ufw"
    return [
        f"{ufw} default deny incoming",
        f"{ufw} default allow outgoing",
        f"{ufw} allow OpenSSH",   # covers port 22 and any custom Port in sshd_config
        f"{ufw} --force enable",
        f"{ufw} status verbose",
    ]


def check_firewall(reporter):
    if _OS == "Darwin":
        _check_firewall_macos(reporter)
        return
    if _OS == "Windows":
        _check_firewall_windows(reporter)
        return

    reporter.begin("FIREWALL STATUS")

    # ufw (Ubuntu / Debian)
    ufw = shutil.which("ufw")
    if ufw:
        try:
            proc = subprocess.run(
                [ufw, "status"], capture_output=True, text=True, timeout=10
            )
            if "status: active" in proc.stdout.lower():
                reporter.ok("ufw is active")
                return
            if "status: inactive" in proc.stdout.lower():
                reporter.finding(
                    "HIGH", "ufw installed but inactive",
                    "A firewall is installed but not running — all ports are reachable.",
                    "Run: sudo ufw enable (SSH will be allowed first to prevent lockout)",
                    fix_cmds=_ufw_enable_cmds(ufw),
                )
                reporter.end("1 firewall issue. Review above.")
                return
        except (OSError, subprocess.TimeoutExpired):
            pass

    # systemd-managed firewalls (firewalld, nftables, iptables)
    systemctl = shutil.which("systemctl")
    if systemctl:
        for svc in ("firewalld", "nftables", "iptables"):
            try:
                proc = subprocess.run(
                    [systemctl, "is-active", "--quiet", svc],
                    capture_output=True, timeout=5,
                )
                if proc.returncode == 0:
                    reporter.ok(f"{svc} is active")
                    return
            except (OSError, subprocess.TimeoutExpired):
                pass

    # iptables direct fallback (needs root to see rules, but gives us a hint)
    iptables = shutil.which("iptables")
    if iptables:
        try:
            proc = subprocess.run(
                [iptables, "-L", "-n", "--line-numbers"],
                capture_output=True, text=True, timeout=10,
            )
            rules = [
                ln for ln in proc.stdout.splitlines()
                if ln and not ln.startswith(("Chain", "target", "num")) and ln.strip()
            ]
            if rules:
                reporter.ok("iptables has active rules")
                return
        except (OSError, subprocess.TimeoutExpired):
            pass

    reporter.finding(
        "HIGH", "No active firewall detected",
        "No firewall appears to be running — all open ports are directly reachable.",
        "Install and enable ufw:  sudo apt install ufw && sudo ufw enable",
        fix_cmds=[
            "DEBIAN_FRONTEND=noninteractive apt-get install -y ufw",
            *_ufw_enable_cmds("/usr/sbin/ufw"),
        ],
    )
    reporter.end("1 firewall issue. Review above.")


# ── Listening services check ──────────────────────────────────────────────────

def _check_listeners_macos(reporter):
    reporter.begin("LISTENING SERVICES")
    try:
        r = subprocess.run(
            ["lsof", "-iTCP", "-sTCP:LISTEN", "-n", "-P"],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        reporter.error(f"lsof failed: {e}")
        return
    pending = []
    for line in r.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        name_part = parts[-1]  # e.g. "*:22" or "127.0.0.1:5432"
        if ":" not in name_part:
            continue
        addr, port_s = name_part.rsplit(":", 1)
        try:
            port = int(port_s)
        except ValueError:
            continue
        if addr in ("127.0.0.1", "::1", "localhost"):
            continue
        proc_name = parts[0]
        info = RISKY_PORTS.get(port) or SPECIAL.get(port)
        if info:
            svc, severity, why, fix = info
        else:
            svc, severity = f"Port {port}", "INFO"
            why = "Service bound to non-localhost interface."
            fix = "Bind to 127.0.0.1 if external access is not needed."
        label = f"port {port}/{addr} [{proc_name}] — {svc}"
        pending.append((severity, label, why, fix, {"port": port, "address": addr}))
    if not pending:
        reporter.ok("No high-risk externally-bound services found")
        reporter.end()
        return
    pending.sort(key=lambda f: SEVERITY_ORDER.get(f[0], 9))
    for severity, label, why, fix, extra in pending:
        reporter.finding(severity, label, why, fix, **extra)
    reporter.end(f"{len(pending)} externally-reachable service(s). Review above.")


_WIN_LOOPBACK = {"127.0.0.1", "::1", "0:0:0:0:0:0:0:1"}


def _check_listeners_windows(reporter):
    reporter.begin("LISTENING SERVICES")
    out, rc = _ps(
        "Get-NetTCPConnection -State Listen | "
        "Select-Object LocalAddress,LocalPort,OwningProcess | ConvertTo-Json"
    )
    if rc != 0 or not out.strip():
        reporter.error("Could not query TCP listeners (requires PowerShell)")
        reporter.end()
        return
    # Also get process names
    pnames, _ = _ps(
        "Get-Process | Select-Object Id,ProcessName | ConvertTo-Json"
    )
    pid_map: dict = {}
    try:
        procs = json.loads(pnames)
        if isinstance(procs, dict):
            procs = [procs]
        pid_map = {str(p["Id"]): p["ProcessName"] for p in procs}
    except Exception:
        pass
    try:
        conns = json.loads(out)
        if isinstance(conns, dict):
            conns = [conns]
    except Exception:
        reporter.error("Could not parse TCP listener output")
        reporter.end()
        return
    pending = []
    seen = set()  # (port, pid) — dual-stack services bind 0.0.0.0 AND ::,
                  # which previously produced every finding twice.
    for c in conns:
        addr = c.get("LocalAddress", "")
        port = c.get("LocalPort", 0)
        pid  = str(c.get("OwningProcess", ""))
        if addr in _WIN_LOOPBACK:
            continue
        key = (port, pid)
        if key in seen:
            continue
        seen.add(key)
        proc_name = pid_map.get(pid, f"PID {pid}")
        info = RISKY_PORTS.get(port) or SPECIAL.get(port)
        if info:
            svc, severity, why, fix = info
        else:
            svc, severity = f"Port {port}", "INFO"
            why = "Service bound to non-localhost interface."
            fix = "Restrict via Windows Firewall if not needed externally."
        label = f"port {port}/{addr} [{proc_name}] — {svc}"
        pending.append((severity, label, why, fix, {"port": port, "address": addr}))
    if not pending:
        reporter.ok("No high-risk externally-bound services found")
        reporter.end()
        return
    pending.sort(key=lambda f: SEVERITY_ORDER.get(f[0], 9))
    for severity, label, why, fix, extra in pending:
        reporter.finding(severity, label, why, fix, **extra)
    reporter.end(f"{len(pending)} externally-reachable service(s). Review above.")


def _parse_ss_addr(local):
    """Parse 'addr:port' or '[addr]:port' from ss -tlnp. Returns (addr, port) or (None, None)."""
    if local.startswith("["):
        end = local.find("]")
        if end == -1:
            return None, None
        addr = local[1:end]
        rest = local[end + 1:]
        port_str = rest.lstrip(":") if rest.startswith(":") else ""
    else:
        colon = local.rfind(":")
        if colon == -1:
            return None, None
        addr, port_str = local[:colon], local[colon + 1:]
    try:
        return addr, int(port_str)
    except ValueError:
        return None, None


_LOCALHOST_ADDRS = {"127.0.0.1", "::1", "localhost"}


def check_listeners(reporter):
    if _OS == "Darwin":
        _check_listeners_macos(reporter)
        return
    if _OS == "Windows":
        _check_listeners_windows(reporter)
        return

    reporter.begin("LISTENING SERVICES")

    ss = shutil.which("ss")
    if not ss:
        reporter.error("'ss' not found (install iproute2) — cannot list listeners")
        return

    try:
        proc = subprocess.run(
            [ss, "-tlnp"], capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        reporter.error(f"Could not run ss: {e}")
        return

    pending = []
    for line in proc.stdout.splitlines()[1:]:   # skip header row
        parts = line.split()
        if len(parts) < 5:
            continue
        addr, port = _parse_ss_addr(parts[4])
        if addr is None or addr in _LOCALHOST_ADDRS:
            continue

        proc_name = ""
        if len(parts) >= 6:
            m = re.search(r'"([^"]+)"', parts[5])
            if m:
                proc_name = m.group(1)

        info = RISKY_PORTS.get(port) or SPECIAL.get(port)
        if info:
            svc, severity, why, fix = info
        else:
            svc, severity = f"Port {port}", "INFO"
            why = "Service is bound to a non-localhost interface — confirm this is intentional."
            fix = "If this service doesn't need to be externally reachable, bind it to 127.0.0.1."

        label = f"port {port}/{addr}"
        if proc_name:
            label += f"  [{proc_name}]"
        label += f"  — {svc}"
        pending.append((
            severity, label, why, fix,
            {"port": port, "address": addr, "process": proc_name},
        ))

    if not pending:
        reporter.ok("No externally-bound services found in risk database")
        return

    pending.sort(key=lambda f: SEVERITY_ORDER.get(f[0], 9))
    if not reporter.json_mode:
        print(f"\n[!] {len(pending)} externally-reachable service(s):")
    for severity, label, why, fix, extra in pending:
        reporter.finding(severity, label, why, fix, **extra)

    crit = sum(1 for f in pending if f[0] == "CRITICAL")
    high = sum(1 for f in pending if f[0] == "HIGH")
    reporter.end(f"{crit} critical, {high} high-risk listeners. Review above.")


# ── World-writable files check ────────────────────────────────────────────────

_WORLD_WRITABLE_DIRS_WINDOWS = [
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
]


def _check_world_writable_windows(reporter):
    reporter.begin("WORLD-WRITABLE FILES")
    findings = []
    for check_dir in _WORLD_WRITABLE_DIRS_WINDOWS:
        if not os.path.isdir(check_dir):
            continue
        out, rc = _ps(
            f'icacls "{check_dir}\\*" 2>$null | '
            "Select-String 'Everyone.*(M|F|W)' | Select-Object -First 10 -ExpandProperty Line",
            timeout=45,
        )
        for line in (out or "").splitlines():
            line = line.strip()
            if line:
                findings.append(line)
    if not findings:
        reporter.ok("No Everyone-writable files found in system directories")
        reporter.end()
        return
    reporter.finding(
        "HIGH", f"{len(findings)} Everyone-writable file(s) in system directories",
        "Files writable by 'Everyone' in system directories can be replaced or hijacked by malware.",
        "Run: icacls <file> /remove Everyone   for each listed file.",
    )
    reporter.end(f"{len(findings)} writable file(s) found.")


_WORLD_WRITABLE_DIRS = [
    "/etc",
    "/usr/bin", "/usr/sbin",
    "/bin", "/sbin",
    "/usr/local/bin", "/usr/local/sbin",
]


def check_world_writable(reporter):
    if _OS == "Windows":
        _check_world_writable_windows(reporter)
        return
    # macOS uses same find approach as Linux

    reporter.begin("WORLD-WRITABLE FILES")

    search = [p for p in _WORLD_WRITABLE_DIRS if os.path.isdir(p)]
    if not search:
        reporter.ok("No standard system directories found to scan")
        return

    find = shutil.which("find")
    if not find:
        reporter.error("'find' not available — cannot check world-writable files")
        return

    try:
        proc = subprocess.run(
            [find] + search + ["-xdev", "-type", "f", "-perm", "-0002"],
            capture_output=True, text=True, timeout=60,
        )
    except subprocess.TimeoutExpired:
        reporter.error("World-writable scan timed out")
        return
    except OSError as e:
        reporter.error(f"Could not run find: {e}")
        return

    files = [f.strip() for f in proc.stdout.splitlines() if f.strip()]
    if not files:
        reporter.ok(f"No world-writable files in {len(search)} scanned dir(s)")
        return

    if not reporter.json_mode:
        print(f"\n[!] {len(files)} world-writable file(s) found:")
    for f in files:
        reporter.finding(
            "HIGH",
            f"World-writable: {f}",
            "Any local user can modify this file; if executed with elevated privileges "
            "this is a privilege-escalation path.",
            f"Run: chmod o-w '{f}'",
            fix_cmds=[f"chmod o-w '{f}'"],
            path=f,
        )
    reporter.end(f"{len(files)} world-writable file(s). Review above.")


# ── SUID / SGID binaries check ────────────────────────────────────────────────

_SUID_SEARCH_DIRS = [
    "/usr/bin", "/usr/sbin",
    "/bin", "/sbin",
    "/usr/local/bin", "/usr/local/sbin",
    "/usr/lib",
]

# Top-level dirs where a SUID binary is suspicious (not a standard system location)
_SUID_SUSPECT_ROOTS = frozenset({"/tmp", "/home", "/var", "/srv", "/opt", "/dev"})


def check_suid(reporter):
    if _OS != "Linux":
        reporter.begin("SUID/SGID BINARIES")
        reporter.ok("SUID/SGID concept does not apply on this platform")
        return

    reporter.begin("SUID / SGID BINARIES")

    search = [p for p in _SUID_SEARCH_DIRS if os.path.isdir(p)]
    find = shutil.which("find")
    if not find:
        reporter.error("'find' not available — cannot scan for SUID/SGID binaries")
        return

    findings = []   # [(path, "SUID"|"SGID")]
    for perm, label in [("-4000", "SUID"), ("-2000", "SGID")]:
        try:
            proc = subprocess.run(
                [find] + search + ["-xdev", "-type", "f", "-perm", perm],
                capture_output=True, text=True, timeout=60,
            )
        except (subprocess.TimeoutExpired, OSError):
            continue
        for f in proc.stdout.splitlines():
            if f.strip():
                findings.append((f.strip(), label))

    if not findings:
        reporter.ok("No SUID/SGID binaries found in scanned paths")
        return

    if not reporter.json_mode:
        print(f"\n[!] {len(findings)} SUID/SGID binary(ies) found:")
    for path, label in sorted(findings):
        top = "/" + path.lstrip("/").split("/")[0]
        if top in _SUID_SUSPECT_ROOTS:
            severity = "CRITICAL"
            why = (f"{label} binary in unusual location — "
                   "potential planted privilege-escalation exploit.")
            fix_cmds = [f"chmod u-s {shlex.quote(path)}"]
        else:
            severity = "INFO"
            why = (f"{label} binary runs as its owner (typically root) regardless of "
                   "who invokes it — verify this is intentional.")
            fix_cmds = None
        reporter.finding(
            severity,
            f"{label}: {path}",
            why,
            f"Remove the setuid/setgid bit if unneeded: chmod u-s '{path}'",
            fix_cmds=fix_cmds,
            path=path,
            suid_type=label,
        )

    suspect = sum(1 for p, _ in findings if ("/" + p.lstrip("/").split("/")[0]) in _SUID_SUSPECT_ROOTS)
    reporter.end(f"{len(findings)} SUID/SGID binaries, {suspect} in suspicious locations.")


# ── Cron job audit ────────────────────────────────────────────────────────────

def _check_scheduled_tasks_windows(reporter):
    reporter.begin("SCHEDULED TASKS")
    out, rc = _ps(
        "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | "
        "Select-Object TaskName,TaskPath,@{N='RunAs';E={$_.Principal.UserId}} | "
        "ConvertTo-Json"
    )
    if rc != 0 or not out.strip():
        reporter.ok("No scheduled tasks found or access denied")
        reporter.end()
        return
    try:
        tasks = json.loads(out)
        if isinstance(tasks, dict):
            tasks = [tasks]
    except Exception:
        reporter.error("Could not parse scheduled tasks output")
        reporter.end()
        return
    # Built-in tasks under \Microsoft\ legitimately run as SYSTEM — flagging
    # them buried real findings under dozens of noise rows.
    suspicious = [t for t in tasks if
                  (t.get("RunAs") or "").upper() in ("SYSTEM", "NT AUTHORITY\\SYSTEM")
                  and not (t.get("TaskPath") or "").startswith("\\Microsoft\\")]
    if not suspicious:
        reporter.ok(f"{len(tasks)} active scheduled task(s) — no non-Microsoft SYSTEM tasks found")
        reporter.end()
        return
    for t in suspicious[:10]:
        tname = t.get("TaskName", "?")
        tpath = t.get("TaskPath", "\\")
        safe_name = tname.replace("'", "''")
        safe_path = tpath.replace("'", "''")
        reporter.finding(
            "REVIEW",
            f"Third-party task runs as SYSTEM: {tname}",
            f"Non-Microsoft task at {tpath} runs with full machine access.",
            "Review in Task Scheduler — disable if not needed.",
            fix_cmds=[f"Disable-ScheduledTask -TaskName '{safe_name}' -TaskPath '{safe_path}'"],
        )
    reporter.end(f"{len(suspicious)} non-Microsoft SYSTEM task(s) found.")


_CRON_FILES       = ["/etc/crontab"]
_CRON_DIRS        = ["/etc/cron.d"]
_CRON_ROOT_SPOOL  = "/var/spool/cron/crontabs/root"


def check_cron(reporter):
    if _OS == "Darwin":
        pass  # crontab works on macOS too — fall through to existing code
    elif _OS == "Windows":
        _check_scheduled_tasks_windows(reporter)
        return

    reporter.begin("CRON JOB AUDIT")

    cron_files = list(_CRON_FILES)
    for d in _CRON_DIRS:
        if os.path.isdir(d):
            try:
                for name in os.listdir(d):
                    fp = os.path.join(d, name)
                    if os.path.isfile(fp):
                        cron_files.append(fp)
            except OSError:
                pass
    if os.path.isfile(_CRON_ROOT_SPOOL):
        cron_files.append(_CRON_ROOT_SPOOL)

    readable = []
    for f in cron_files:
        try:
            with open(f) as fh:
                readable.append((f, fh.read()))
        except (PermissionError, OSError):
            pass  # needs sudo or doesn't exist; skip silently

    if not readable:
        reporter.ok("No readable cron files found (re-run with sudo for full coverage)")
        return

    pending = []
    for cron_file, content in readable:
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if re.match(r'^[A-Z_]+=', stripped):   # variable assignment
                continue
            for token in stripped.split():
                if not token.startswith("/"):
                    continue
                # Strip shell redirects or operators that may be attached
                token = re.split(r'[<>&|;]', token)[0]
                if not token or not os.path.isfile(token):
                    continue
                try:
                    if os.stat(token).st_mode & 0o002:  # world-writable
                        pending.append((cron_file, token))
                except OSError:
                    pass

    if not pending:
        reporter.ok(f"No world-writable scripts in {len(readable)} cron file(s)")
        return

    if not reporter.json_mode:
        print(f"\n[!] {len(pending)} world-writable cron script(s) found:")
    for cron_file, script in pending:
        reporter.finding(
            "CRITICAL",
            f"World-writable cron script: {script}",
            f"Any local user can overwrite {script}, "
            f"which is referenced in {cron_file} and may run as root.",
            f"Run: chmod o-w '{script}'",
            fix_cmds=[f"chmod o-w {shlex.quote(script)}"],
            cron_file=cron_file,
            script=script,
        )
    reporter.end(f"{len(pending)} critical cron issue(s). Review above.")


# ── Kernel hardening check ────────────────────────────────────────────────────

def _check_kernel_macos(reporter):
    reporter.begin("KERNEL HARDENING (macOS)")
    issues = []
    checks = [
        ("net.inet.ip.forwarding", "1", "MEDIUM", "IP forwarding enabled — machine routes packets"),
    ]
    for key, bad_val, sev, desc in checks:
        try:
            r = subprocess.run(["sysctl", "-n", key], capture_output=True, text=True, timeout=5)
            val = r.stdout.strip()
            if val == bad_val:
                issues.append((sev, f"{key} = {val}", desc,
                               f"Set: sudo sysctl -w {key}=0"))
        except (OSError, subprocess.TimeoutExpired):
            pass
    # Check kernel boot args for security-disabling flags
    try:
        r = subprocess.run(["sysctl", "-n", "kern.bootargs"], capture_output=True, text=True, timeout=5)
        val = r.stdout.strip()
        dangerous = [f for f in ("kext-dev-mode=1", "amfi_get_out_of_my_way=1", "cs_enforcement_disable=1") if f in val]
        if dangerous:
            issues.append(("HIGH", f"Dangerous boot args: {', '.join(dangerous)}",
                           "These boot arguments disable key macOS security features (SIP, AMFI, codesigning).",
                           "Remove from boot args in Recovery Mode → csrutil authenticated-root disable reversal"))
    except (OSError, subprocess.TimeoutExpired):
        pass
    # SIP check
    try:
        r = subprocess.run(["csrutil", "status"], capture_output=True, text=True, timeout=5)
        if "disabled" in r.stdout.lower():
            issues.append(("HIGH", "System Integrity Protection (SIP) is disabled",
                           "SIP prevents even root from modifying critical system files.",
                           "Re-enable SIP: boot to Recovery, run csrutil enable"))
    except (OSError, subprocess.TimeoutExpired):
        pass
    if not issues:
        reporter.ok("No macOS kernel hardening issues found")
        return
    for sev, label, why, fix in issues:
        reporter.finding(sev, label, why, fix)
    reporter.end(f"{len(issues)} issue(s) found.")


def _check_kernel_windows(reporter):
    reporter.begin("KERNEL HARDENING (Windows)")
    issues = []

    # UAC
    out, rc = _ps(
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
        "| Select-Object EnableLUA | ConvertTo-Json"
    )
    if rc == 0 and out.strip():
        try:
            if not json.loads(out).get("EnableLUA", 1):
                issues.append(("HIGH", "UAC (User Account Control) is disabled",
                               "UAC prevents privilege escalation — disabling it gives any process admin rights.",
                               "Enable via Windows Security or run the fix command.",
                               ["Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows"
                                "\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1"]))
        except Exception:
            pass

    # Secure Boot
    out, rc = _ps("Confirm-SecureBootUEFI 2>$null")
    if "False" in out:
        issues.append(("MEDIUM", "Secure Boot is disabled",
                       "Secure Boot prevents unauthorized bootloaders and rootkits at boot time.",
                       "Enable Secure Boot in UEFI/BIOS firmware settings.",
                       None))  # requires firmware — cannot automate

    # Windows Defender real-time protection
    out, rc = _ps("Get-MpPreference | Select-Object DisableRealtimeMonitoring | ConvertTo-Json")
    if rc == 0 and out.strip():
        try:
            if json.loads(out).get("DisableRealtimeMonitoring"):
                issues.append(("HIGH", "Windows Defender real-time protection is off",
                               "Real-time protection is the primary on-access malware defence.",
                               "Enable: Set-MpPreference -DisableRealtimeMonitoring $false",
                               ["Set-MpPreference -DisableRealtimeMonitoring $false"]))
        except Exception:
            pass

    # ASLR — MoveImages=0 means explicitly disabled system-wide
    out, rc = _ps(
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management' "
        "-Name MoveImages -ErrorAction SilentlyContinue | Select-Object -ExpandProperty MoveImages"
    )
    if rc == 0 and out.strip():
        try:
            if int(out.strip()) == 0:
                issues.append(("CRITICAL", "ASLR is explicitly disabled (MoveImages=0)",
                               "Address Space Layout Randomization is a core exploit-mitigation technique. "
                               "Disabling it makes memory-corruption exploits significantly easier.",
                               "Enable: Set-ItemProperty '...\\Memory Management' -Name MoveImages -Value 1",
                               ["Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control"
                                "\\Session Manager\\Memory Management' -Name MoveImages -Value 1"]))
        except ValueError:
            pass

    # DEP / NX policy
    out, rc = _ps("bcdedit /enum '{current}' 2>$null")
    if rc == 0:
        for line in out.splitlines():
            if "nx" in line.lower() and "alwaysoff" in line.lower():
                issues.append(("CRITICAL", "Data Execution Prevention (DEP) is disabled",
                               "DEP prevents code execution from data pages, blocking many exploit payloads.",
                               "Enable: bcdedit /set nx AlwaysOn  (requires reboot)",
                               ["bcdedit /set nx AlwaysOn"]))
                break

    # BitLocker on the system drive
    out, rc = _ps(
        "Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue "
        "| Select-Object -ExpandProperty ProtectionStatus"
    )
    if rc == 0 and out.strip():
        try:
            if int(out.strip()) == 0:   # 0 = Off, 1 = On
                issues.append(("HIGH", "BitLocker is not enabled on C:",
                               "Without full-disk encryption, data is readable if the device is lost or stolen.",
                               "Enable: Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256",
                               None))  # requires key backup decision — user must run manually
        except ValueError:
            pass

    # PowerShell execution policy (machine scope)
    out, rc = _ps("Get-ExecutionPolicy -Scope LocalMachine")
    if rc == 0 and out.strip():
        policy = out.strip().lower()
        if policy == "bypass":
            issues.append(("CRITICAL", "PowerShell execution policy is Bypass",
                           "Bypass allows any script to run without restriction or warning — "
                           "a common initial-access and persistence technique.",
                           "Set: Set-ExecutionPolicy RemoteSigned -Scope LocalMachine",
                           ["Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force"]))
        elif policy == "unrestricted":
            issues.append(("HIGH", "PowerShell execution policy is Unrestricted",
                           "Unrestricted permits unsigned remote scripts to run, "
                           "making script-based attacks easier.",
                           "Set: Set-ExecutionPolicy RemoteSigned -Scope LocalMachine",
                           ["Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force"]))

    # LSA Protection (RunAsPPL) — prevents LSASS credential dumping (Mimikatz etc.)
    out, rc = _ps(
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
        "-Name RunAsPPL -ErrorAction SilentlyContinue | Select-Object -ExpandProperty RunAsPPL"
    )
    if rc == 0 and out.strip():
        try:
            if int(out.strip()) == 0:
                issues.append(("MEDIUM", "LSA Protection (RunAsPPL) is disabled",
                               "Without LSA Protection, tools like Mimikatz can dump credentials "
                               "directly from LSASS memory.",
                               "Enable (requires reboot): Set-ItemProperty '...\\Lsa' -Name RunAsPPL -Value 1",
                               ["Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'"
                                " -Name RunAsPPL -Value 1"]))
        except ValueError:
            pass

    # SMB signing — prevents NTLM relay attacks
    out, rc = _ps(
        "Get-SmbServerConfiguration | Select-Object -ExpandProperty RequireSecuritySignature"
    )
    if rc == 0 and out.strip().lower() in ("false", "0"):
        issues.append(("MEDIUM", "SMB signing is not required on this server",
                       "Without required SMB signing, NTLM relay attacks can impersonate this host "
                       "to reach other systems on the network.",
                       "Enable: Set-SmbServerConfiguration -RequireSecuritySignature $true -Force",
                       ["Set-SmbServerConfiguration -RequireSecuritySignature $true -Force"]))

    if not issues:
        reporter.ok("No Windows kernel/security hardening issues found")
        reporter.end()
        return
    for sev, label, why, fix, fix_cmds in issues:
        reporter.finding(sev, label, why, fix, fix_cmds=fix_cmds)
    reporter.end(f"{len(issues)} issue(s) found.")


def _read_sysctl(key):
    """Read a sysctl value from /proc/sys/.  Returns (value_str, error_or_None)."""
    path = "/proc/sys/" + key.replace(".", "/")
    try:
        with open(path) as fh:
            return fh.read().strip(), None
    except FileNotFoundError:
        return None, "not found"
    except OSError as e:
        return None, str(e)


# Each rule is (key, check_fn, why, fix).
# check_fn(value_str) -> (severity, label) if bad, else None.
# (key, check_fn, why, fix_description, recommended_value)
# recommended_value drives the auto-fix: `sysctl -w key=recommended_value`
_SYSCTL_RULES = [
    (
        "kernel.randomize_va_space",
        lambda v: (
            ("CRITICAL", f"ASLR disabled (kernel.randomize_va_space={v})")
            if v == "0" else
            ("HIGH", f"ASLR partial (kernel.randomize_va_space={v}; should be 2)")
            if v != "2" else None
        ),
        "ASLR makes exploitation of memory-corruption bugs far harder. "
        "Value 2 enables full randomization of stack, heap, and mmap.",
        "echo 'kernel.randomize_va_space=2' | sudo tee /etc/sysctl.d/99-hardening.conf"
        " && sudo sysctl -p /etc/sysctl.d/99-hardening.conf",
        "2",
    ),
    (
        "net.ipv4.tcp_syncookies",
        lambda v: ("HIGH", "SYN-flood protection disabled (net.ipv4.tcp_syncookies=0)")
        if v == "0" else None,
        "SYN cookies protect against SYN-flood DoS attacks that exhaust connection queues.",
        "Set net.ipv4.tcp_syncookies=1 in /etc/sysctl.d/99-hardening.conf",
        "1",
    ),
    (
        "fs.suid_dumpable",
        lambda v: ("HIGH", f"SUID core dumps enabled (fs.suid_dumpable={v})")
        if v != "0" else None,
        "Non-zero suid_dumpable lets setuid processes produce core dumps, "
        "potentially exposing secrets from privileged memory.",
        "Set fs.suid_dumpable=0 in /etc/sysctl.d/99-hardening.conf",
        "0",
    ),
    (
        "net.ipv4.ip_forward",
        lambda v: ("HIGH", "IPv4 forwarding enabled (net.ipv4.ip_forward=1)")
        if v == "1" else None,
        "IP forwarding turns this host into a router; unnecessary on a server "
        "and can be abused for traffic interception.",
        "Set net.ipv4.ip_forward=0 in /etc/sysctl.d/99-hardening.conf "
        "(unless this host is intentionally a router)",
        "0",
    ),
    (
        "kernel.dmesg_restrict",
        lambda v: ("MEDIUM", "Kernel log unrestricted (kernel.dmesg_restrict=0)")
        if v == "0" else None,
        "Kernel logs can leak physical addresses, module paths, and other data "
        "useful for privilege escalation.",
        "Set kernel.dmesg_restrict=1 in /etc/sysctl.d/99-hardening.conf",
        "1",
    ),
    (
        "kernel.kptr_restrict",
        lambda v: ("MEDIUM", f"Kernel pointer exposure not restricted (kernel.kptr_restrict={v})")
        if v == "0" else None,
        "kptr_restrict=0 leaks kernel symbol addresses via /proc, "
        "helping attackers defeat KASLR.",
        "Set kernel.kptr_restrict=1 in /etc/sysctl.d/99-hardening.conf",
        "1",
    ),
    (
        "net.ipv4.conf.all.accept_redirects",
        lambda v: ("MEDIUM", "ICMP redirect acceptance enabled (accept_redirects=1)")
        if v == "1" else None,
        "Accepting ICMP redirects allows a malicious router to silently "
        "reroute traffic on this host.",
        "Set net.ipv4.conf.all.accept_redirects=0 in /etc/sysctl.d/99-hardening.conf",
        "0",
    ),
    (
        "net.ipv6.conf.all.accept_redirects",
        lambda v: ("MEDIUM", "IPv6 ICMP redirect acceptance enabled")
        if v == "1" else None,
        "Same as IPv4: accepting ICMPv6 redirects allows silent traffic rerouting.",
        "Set net.ipv6.conf.all.accept_redirects=0 in /etc/sysctl.d/99-hardening.conf",
        "0",
    ),
    (
        "net.ipv4.conf.all.send_redirects",
        lambda v: ("MEDIUM", "ICMP redirect sending enabled (send_redirects=1)")
        if v == "1" else None,
        "Sending ICMP redirects is unnecessary on a non-router and "
        "can be used in network spoofing attacks.",
        "Set net.ipv4.conf.all.send_redirects=0 in /etc/sysctl.d/99-hardening.conf",
        "0",
    ),
    (
        "net.ipv4.conf.all.rp_filter",
        lambda v: ("MEDIUM", f"Reverse-path filtering disabled (rp_filter={v})")
        if v == "0" else None,
        "rp_filter=0 allows packets with spoofed source addresses, "
        "enabling IP spoofing attacks.",
        "Set net.ipv4.conf.all.rp_filter=1 in /etc/sysctl.d/99-hardening.conf",
        "1",
    ),
]


def check_kernel_hardening(reporter):
    if _OS == "Darwin":
        _check_kernel_macos(reporter)
        return
    if _OS == "Windows":
        _check_kernel_windows(reporter)
        return

    reporter.begin("KERNEL HARDENING", "checking sysctl security parameters")

    if not os.path.isdir("/proc/sys"):
        reporter.info("/proc/sys not available; skipping kernel hardening check.")
        reporter.end()
        return

    pending = []
    unreadable = []
    for key, check_fn, why, fix, recommended in _SYSCTL_RULES:
        val, err = _read_sysctl(key)
        if err:
            if err != "not found":
                unreadable.append(key)
            continue
        result = check_fn(val)
        if result:
            sev, label = result
            fix_cmds = [f"sysctl -w {key}={recommended}"] if recommended else []
            pending.append((sev, label, why, fix, fix_cmds))

    pending.sort(key=lambda f: SEVERITY_ORDER.get(f[0], 9))
    for sev, label, why, fix, fix_cmds in pending:
        reporter.finding(sev, label, why, fix, fix_cmds=fix_cmds)

    if unreadable:
        reporter.info(f"Could not read {len(unreadable)} sysctl key(s): {', '.join(unreadable)}")

    if not pending:
        reporter.ok("All checked kernel parameters meet recommended values.")

    count = sum(1 for s, *_ in pending if s in ("CRITICAL", "HIGH"))
    reporter.end(
        f"{len(pending)} hardening issue(s) found." if pending
        else "All kernel hardening parameters OK."
    )
    return count


# ── Sensitive file permissions ────────────────────────────────────────────────

_WIN_SENSITIVE_HIVES = [
    r"C:\Windows\System32\config\SAM",
    r"C:\Windows\System32\config\SYSTEM",
    r"C:\Windows\Repair\SAM",      # older backup — often forgotten and mis-permissioned
    r"C:\Windows\Repair\SYSTEM",
]

_WIN_UNATTEND_PATHS = [
    r"C:\Windows\Panther\Unattend.xml",
    r"C:\Windows\Panther\Unattended.xml",
    r"C:\Windows\system32\sysprep\Unattend.xml",
    r"C:\unattend.xml",
    r"C:\Autounattend.xml",
]


def _check_sensitive_perms_windows(reporter):
    reporter.begin("SENSITIVE FILE PERMISSIONS")
    found_any = False

    # Registry hive files readable by Everyone
    for path in _WIN_SENSITIVE_HIVES:
        if not os.path.exists(path):
            continue
        out, rc = _ps(
            f'(Get-Acl "{path}").Access '
            "| Select-Object IdentityReference,FileSystemRights | ConvertTo-Json"
        )
        if rc == 0 and "Everyone" in out:
            reporter.finding(
                "HIGH", f"Sensitive hive readable by Everyone: {path}",
                "SAM/SYSTEM hive readable by Everyone exposes password hashes.",
                f'Remove Everyone ACL: icacls "{path}" /remove Everyone',
                fix_cmds=[f'icacls "{path}" /remove Everyone'],
            )
            found_any = True

    # Unattended installation files — frequently contain cleartext passwords
    for path in _WIN_UNATTEND_PATHS:
        if not os.path.exists(path):
            continue
        try:
            with open(path, errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue
        if "<Password>" in content or "AutoLogon" in content or "AdministratorPassword" in content:
            reporter.finding(
                "CRITICAL",
                f"Unattended install file with credentials: {path}",
                f"'{path}' contains password or AutoLogon elements in cleartext — "
                "any local user can read these credentials.",
                "Delete the file after confirming the machine is fully provisioned.",
                fix_cmds=[f"Remove-Item -Path '{path}' -Force"],
            )
            found_any = True

    if not found_any:
        reporter.ok("No overly-permissive sensitive files found")
    reporter.end()


# (path, bad_mode_bit, severity, label, why, fix_description, fix_cmds)
_SENSITIVE_FILE_RULES = [
    ("/etc/shadow",  0o004, "CRITICAL",
     "/etc/shadow world-readable",
     "Hashed passwords are readable by any local user, enabling offline cracking.",
     "chmod 640 /etc/shadow && chown root:shadow /etc/shadow",
     ["chmod 640 /etc/shadow", "chown root:shadow /etc/shadow"]),
    ("/etc/shadow",  0o002, "CRITICAL",
     "/etc/shadow world-writable",
     "Any local user can overwrite password hashes, instantly taking any account.",
     "chmod 640 /etc/shadow && chown root:shadow /etc/shadow",
     ["chmod 640 /etc/shadow", "chown root:shadow /etc/shadow"]),
    ("/etc/gshadow", 0o004, "HIGH",
     "/etc/gshadow world-readable",
     "Group shadow file exposes group password hashes.",
     "chmod 640 /etc/gshadow && chown root:shadow /etc/gshadow",
     ["chmod 640 /etc/gshadow", "chown root:shadow /etc/gshadow"]),
    ("/etc/passwd",  0o002, "CRITICAL",
     "/etc/passwd world-writable",
     "Any local user can add or modify accounts, including inserting a UID 0 entry.",
     "chmod 644 /etc/passwd",
     ["chmod 644 /etc/passwd"]),
    ("/etc/sudoers", 0o004, "HIGH",
     "/etc/sudoers world-readable",
     "Sudo rules visible to any user may reveal privilege paths.",
     "chmod 440 /etc/sudoers",
     ["chmod 440 /etc/sudoers"]),
    ("/etc/sudoers", 0o002, "CRITICAL",
     "/etc/sudoers world-writable",
     "Any local user can grant themselves full sudo and escalate to root.",
     "chmod 440 /etc/sudoers",
     ["chmod 440 /etc/sudoers"]),
]


_SENSITIVE_FILE_RULES_MACOS_EXTRA = [
    ("/private/etc/shadow", 0o004, "CRITICAL",
     "/private/etc/shadow world-readable",
     "Password hashes are readable by any local user.",
     "chmod 640 /private/etc/shadow",
     ["chmod 640 /private/etc/shadow"]),
]


def check_sensitive_perms(reporter, rules=None, ssh_key_glob="/etc/ssh/ssh_host_*_key"):
    if _OS == "Darwin":
        if rules is None:
            rules = list(_SENSITIVE_FILE_RULES) + _SENSITIVE_FILE_RULES_MACOS_EXTRA
    elif _OS == "Windows":
        _check_sensitive_perms_windows(reporter)
        return
    # Fall through to existing Linux/macOS implementation

    reporter.begin("SENSITIVE FILE PERMISSIONS", "checking critical system file modes")

    if rules is None:
        rules = _SENSITIVE_FILE_RULES

    pending = []

    for path, bad_bit, sev, label, why, fix, fix_cmds in rules:
        try:
            mode = os.stat(path).st_mode
        except FileNotFoundError:
            continue
        except OSError:
            continue
        if mode & bad_bit:
            pending.append((sev, label, why, fix, fix_cmds))

    # SSH host private keys — should not be readable by group or world
    import glob as _glob
    for key_path in sorted(_glob.glob(ssh_key_glob)):
        try:
            mode = os.stat(key_path).st_mode
        except OSError:
            continue
        if mode & 0o044:  # group-readable (040) or world-readable (004)
            pending.append((
                "CRITICAL",
                f"SSH host private key readable by non-root: {key_path}",
                "Exposure of SSH host private keys enables MITM attacks on "
                "every connection to this server.",
                f"chmod 600 {key_path}",
                [f"chmod 600 {key_path}"],
            ))

    pending.sort(key=lambda f: SEVERITY_ORDER.get(f[0], 9))
    for sev, label, why, fix, fix_cmds in pending:
        reporter.finding(sev, label, why, fix, fix_cmds=fix_cmds)

    if not pending:
        reporter.ok("Sensitive file permissions look correct.")

    reporter.end(
        f"{len(pending)} permission issue(s) found." if pending
        else "All sensitive file permissions OK."
    )


# ── User account security ──────────────────────────────────────────────────────

def _check_user_accounts_windows(reporter):
    reporter.begin("USER ACCOUNTS")
    out, rc = _ps(
        "Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,PasswordLastSet "
        "| ConvertTo-Json"
    )
    if rc != 0 or not out.strip():
        reporter.error("Could not query local users (requires admin)")
        reporter.end()
        return
    try:
        users = json.loads(out)
        if isinstance(users, dict):
            users = [users]
    except Exception:
        reporter.error("Could not parse user list")
        reporter.end()
        return
    issues = []
    for u in users:
        if not u.get("Enabled"):
            continue
        # PasswordRequired=False alone can be set on Windows Hello/PIN accounts that
        # are perfectly secure. Only flag when PasswordLastSet is also null, meaning
        # no password has ever been set on the account.
        if not u.get("PasswordRequired", True) and u.get("PasswordLastSet") is None:
            issues.append(("CRITICAL", f"User '{u['Name']}' has no password set",
                           "Account has no password — anyone can log in without authenticating.",
                           f"net user \"{u['Name']}\" *"))
    if not issues:
        reporter.ok(f"{len(users)} local user(s) checked — no passwordless accounts found")
        reporter.end()
        return
    for sev, label, why, fix in issues:
        reporter.finding(sev, label, why, fix)
    reporter.end(f"{len(issues)} user account issue(s) found.")


def check_user_accounts(reporter):
    if _OS == "Darwin":
        pass  # /etc/passwd exists on macOS — fall through
    elif _OS == "Windows":
        _check_user_accounts_windows(reporter)
        return

    reporter.begin("USER ACCOUNTS", "checking for privileged account anomalies")

    pending = []  # [(sev, label, why, fix, fix_cmds_or_none)]

    # Parse /etc/passwd for extra UID-0 accounts
    try:
        with open("/etc/passwd") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) < 4:
                    continue
                username, _, uid = parts[0], parts[1], parts[2]
                if uid == "0" and username != "root":
                    pending.append((
                        "CRITICAL",
                        f"Extra UID-0 account: {username}",
                        "Any account with UID 0 has full root privileges, "
                        "bypassing sudo and PAM controls.",
                        f"Investigate '{username}'; change its UID or remove the account.",
                        None,  # too risky to auto-remove; human must decide
                    ))
    except OSError as e:
        reporter.error(f"Could not read /etc/passwd: {e}")
        reporter.end()
        return

    # Parse /etc/shadow for accounts with empty password hash (requires root)
    try:
        with open("/etc/shadow") as fh:
            for line in fh:
                parts = line.strip().split(":")
                if len(parts) < 2:
                    continue
                username, pw_hash = parts[0], parts[1]
                if pw_hash == "":
                    pending.append((
                        "CRITICAL",
                        f"Account with empty password: {username}",
                        "An account with no password can be accessed by "
                        "any local or remote user.",
                        f"Lock the account: passwd -l {username}",
                        [f"passwd -l {shlex.quote(username)}"],
                    ))
    except PermissionError:
        pass  # normal — /etc/shadow is root-only
    except FileNotFoundError:
        pass
    except OSError as e:
        reporter.info(f"Could not read /etc/shadow: {e}")

    pending.sort(key=lambda f: SEVERITY_ORDER.get(f[0], 9))
    for sev, label, why, fix, fix_cmds in pending:
        reporter.finding(sev, label, why, fix, fix_cmds=fix_cmds)

    if not pending:
        reporter.ok("No extra UID-0 accounts or empty passwords found.")

    reporter.end(
        f"{len(pending)} account issue(s) found." if pending
        else "User accounts OK."
    )


# ── Docker socket ──────────────────────────────────────────────────────────────

def _check_docker_socket_windows(reporter):
    pipe_path = r"\\.\pipe\docker_engine"
    reporter.begin("DOCKER SOCKET", pipe_path)

    if not shutil.which("docker"):
        reporter.ok("Docker CLI not found — Docker not installed.")
        reporter.end()
        return

    out, rc = _ps(
        f"(Get-Acl -Path '{pipe_path}' -ErrorAction SilentlyContinue).Access "
        "| Select-Object IdentityReference,FileSystemRights | ConvertTo-Json"
    )
    if rc != 0 or not out.strip() or out.strip() == "null":
        reporter.ok("Docker named pipe not found — Docker not running.")
        reporter.end()
        return

    try:
        acls = json.loads(out)
        if isinstance(acls, dict):
            acls = [acls]
        for acl in acls:
            identity = str(acl.get("IdentityReference", "")).lower()
            rights = str(acl.get("FileSystemRights", ""))
            broad = "everyone" in identity or (
                "users" in identity and "docker" not in identity
                and "power" not in identity
            )
            if broad and any(r in rights for r in ("FullControl", "Write", "Modify", "268435456")):
                reporter.finding(
                    "HIGH",
                    f"Docker named pipe broadly accessible: {acl.get('IdentityReference')}",
                    "Broad access to the Docker named pipe lets unprivileged users run containers "
                    "and escalate to SYSTEM by mounting the host filesystem.",
                    "In Docker Desktop Settings, restrict the pipe to the docker-users group "
                    "or Administrators only.",
                )
                reporter.end()
                return
        reporter.ok("Docker named pipe ACL looks appropriate.")
    except Exception:
        reporter.error("Could not parse Docker named pipe ACL")
    reporter.end()


def check_docker_socket(reporter, sock_path="/var/run/docker.sock"):
    if _OS == "Windows":
        _check_docker_socket_windows(reporter)
        return
    # macOS uses same /var/run/docker.sock path — fall through

    reporter.begin("DOCKER SOCKET", sock_path)

    if not os.path.exists(sock_path):
        reporter.ok("Docker socket absent — Docker not running or not installed.")
        reporter.end()
        return

    try:
        mode = os.stat(sock_path).st_mode
    except OSError as e:
        reporter.error(f"Could not stat {sock_path}: {e}")
        reporter.end()
        return

    if mode & 0o002:
        reporter.finding(
            "CRITICAL",
            "Docker socket is world-writable",
            "Any local user can issue Docker API commands and trivially escalate "
            "to root by mounting the host filesystem inside a container.",
            f"chmod 660 {sock_path} && chown root:docker {sock_path}",
            fix_cmds=[f"chmod 660 {sock_path}"],
        )
    elif mode & 0o004:
        reporter.finding(
            "HIGH",
            "Docker socket is world-readable",
            "World-readable Docker socket leaks container metadata and "
            "may enable read-only API access by any local user.",
            f"chmod 660 {sock_path}",
            fix_cmds=[f"chmod 660 {sock_path}"],
        )
    else:
        reporter.ok("Docker socket is not world-accessible.")

    reporter.end()


# ── Auth log analysis ──────────────────────────────────────────────────────────

def _check_auth_log_macos(reporter):
    reporter.begin("AUTH LOG ANALYSIS (macOS)")
    # `log show --last 24h` routinely takes minutes on real machines and blew
    # the old 30 s timeout, surfacing as a scan error. A 6 h window with a
    # 60 s budget completes reliably; if it still can't, skip gracefully.
    try:
        r = subprocess.run(
            ["log", "show", "--predicate",
             'process == "sshd" OR process == "sudo"',
             "--last", "6h", "--style", "compact"],
            capture_output=True, text=True, errors="replace", timeout=60,
        )
        lines = r.stdout.splitlines()
    except subprocess.TimeoutExpired:
        reporter.ok("Auth log query timed out (unified log is slow on this Mac) — skipped")
        reporter.end()
        return
    except OSError as e:
        reporter.error(f"log show failed: {e}")
        reporter.end()
        return
    failed = [l for l in lines if "failed" in l.lower() or "invalid user" in l.lower()]
    sudo_fail = [l for l in lines if "incorrect password" in l.lower()]
    if len(failed) > 20:
        reporter.finding(
            "HIGH", f"{len(failed)} SSH authentication failures in last 6h",
            "High failure rate indicates brute-force or credential-stuffing attacks.",
            "Consider: fail2ban, SSH key-only auth, or port change.",
        )
    elif failed:
        reporter.finding(
            "REVIEW", f"{len(failed)} SSH authentication failure(s) in last 6h",
            "Some failed SSH logins detected.",
            "Monitor for increases — consider key-only authentication.",
        )
    if sudo_fail:
        reporter.finding(
            "MEDIUM", f"{len(sudo_fail)} sudo authentication failure(s)",
            "Failed sudo attempts may indicate attempted privilege escalation.",
            "Review which users are attempting sudo.",
        )
    if not failed and not sudo_fail:
        reporter.ok("No SSH brute-force or sudo failures in last 6h")
    reporter.end()


def _check_auth_log_windows(reporter):
    reporter.begin("AUTH LOG ANALYSIS (Windows)")
    # Event IDs: 4625 = failed logon. Security log requires admin to read.
    out, rc = _ps(
        "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-24)} "
        "-ErrorAction Stop 2>$null | Measure-Object | Select-Object Count | ConvertTo-Json"
    )
    if rc != 0 or not out.strip():
        reporter.error(
            "Could not read Security event log — re-run as Administrator for auth log analysis"
        )
        reporter.end()
        return
    count = 0
    try:
        count = json.loads(out).get("Count", 0) or 0
    except Exception:
        pass
    if count > 50:
        reporter.finding(
            "HIGH", f"{count} failed Windows logon events in last 24h",
            "High volume of failed logons — possible brute-force or password spray.",
            "Review Security event log; consider Account Lockout Policy.",
        )
    elif count > 5:
        reporter.finding(
            "REVIEW", f"{count} failed Windows logon event(s) in last 24h",
            "Some failed logon attempts detected.",
            "Monitor Event ID 4625 in Security log.",
        )
    else:
        reporter.ok(f"Only {count} failed logon event(s) in last 24h")
    reporter.end()


_AUTH_LOGS = ["/var/log/auth.log", "/var/log/secure"]

_RE_FAILED  = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.:a-fA-F]+)")
_RE_INVALID = re.compile(r"Invalid user \S+ from ([\d.:a-fA-F]+)")
_RE_ACCEPT  = re.compile(r"Accepted (?:password|publickey) for (\S+) from ([\d.:a-fA-F]+)")
_RE_SUDO    = re.compile(r"sudo:.*authentication failure", re.IGNORECASE)


def check_auth_log(reporter, log_paths=None):
    if _OS == "Darwin":
        _check_auth_log_macos(reporter)
        return
    if _OS == "Windows":
        _check_auth_log_windows(reporter)
        return

    if log_paths is None:
        log_paths = [p for p in _AUTH_LOGS if os.path.exists(p)]

    reporter.begin("AUTH LOG ANALYSIS", "checking for brute-force and intrusion attempts")

    if not log_paths:
        reporter.info("No auth log found (/var/log/auth.log, /var/log/secure).")
        reporter.end()
        return

    from collections import Counter
    failed_ips:   Counter = Counter()
    failed_users: Counter = Counter()
    invalid_count = 0
    root_failures = 0
    sudo_failures = 0

    for log_path in log_paths:
        try:
            with open(log_path, errors="replace") as fh:
                for line in fh:
                    m = _RE_FAILED.search(line)
                    if m:
                        user, ip = m.group(1), m.group(2)
                        failed_ips[ip] += 1
                        failed_users[user] += 1
                        if user == "root":
                            root_failures += 1
                        continue
                    if _RE_INVALID.search(line):
                        invalid_count += 1
                        continue
                    if _RE_SUDO.search(line):
                        sudo_failures += 1
        except PermissionError:
            reporter.error(
                f"Cannot read {log_path} — re-run with sudo for auth log analysis."
            )
            reporter.end()
            return
        except OSError as e:
            reporter.error(f"Could not read {log_path}: {e}")
            reporter.end()
            return

    total_failures = sum(failed_ips.values()) + invalid_count
    unique_ips     = len(failed_ips)
    top_attackers  = failed_ips.most_common(5)

    if total_failures >= 500:
        ssh_sev = "HIGH"
    elif total_failures >= 50:
        ssh_sev = "MEDIUM"
    elif total_failures > 0:
        ssh_sev = "REVIEW"
    else:
        ssh_sev = None

    if ssh_sev:
        top_str = ", ".join(f"{ip}({n})" for ip, n in top_attackers[:3])
        reporter.finding(
            ssh_sev,
            f"{total_failures} failed SSH login attempt(s) from {unique_ips} IP(s)",
            f"SSH brute-force activity detected. Top sources: {top_str}. "
            f"This indicates your SSH port is being actively scanned.",
            "Install fail2ban to auto-block repeat offenders, or move SSH to a non-standard port.",
            fix_cmds=["apt-get install -y fail2ban && systemctl enable --now fail2ban"],
        )

    if root_failures >= 10:
        root_sev = "HIGH"
    elif root_failures > 0:
        root_sev = "MEDIUM"
    else:
        root_sev = None

    if root_sev:
        reporter.finding(
            root_sev,
            f"{root_failures} failed root SSH login attempt(s)",
            "Direct root login via SSH is being targeted. "
            "Root SSH access should be disabled — use a normal user + sudo instead.",
            "Set PermitRootLogin no in /etc/ssh/sshd_config and reload sshd.",
            fix_cmds=[
                "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
                "systemctl reload sshd",
            ],
        )

    if sudo_failures > 0:
        reporter.finding(
            "REVIEW",
            f"{sudo_failures} sudo authentication failure(s)",
            "Failed sudo attempts may indicate a compromised or probing account.",
            "Review /var/log/auth.log for the user and timing.",
        )

    if total_failures == 0 and root_failures == 0 and sudo_failures == 0:
        reporter.ok("No failed login attempts found in auth log.")

    reporter.end(
        f"{total_failures} failed SSH attempt(s) from {unique_ips} unique IP(s)."
        if total_failures else None
    )


# ── Malware / antivirus scan ───────────────────────────────────────────────────

_WIN_AUTORUN_KEYS = [
    r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
]
_WIN_SUSPICIOUS_AUTORUN = re.compile(
    r"(%temp%|\\temp\\|\\tmp\\|appdata\\local\\temp"
    r"|\.vbs|\.js|powershell[^\w].*-enc[^o]|cmd[^\w].*/c\s)",
    re.IGNORECASE,
)
_WIN_EXEC_EXTS = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr", ".com"}


def _check_windows_registry_persistence(reporter):
    """Flag suspicious entries in common Windows autostart registry keys."""
    for key in _WIN_AUTORUN_KEYS:
        out, rc = _ps(
            f"Get-ItemProperty -Path '{key}' -ErrorAction SilentlyContinue | ConvertTo-Json"
        )
        if rc != 0 or not out.strip():
            continue
        try:
            props = json.loads(out)
            if not isinstance(props, dict):
                continue
            for name, val in props.items():
                if name.startswith("PS"):   # PowerShell metadata properties
                    continue
                if _WIN_SUSPICIOUS_AUTORUN.search(str(val)):
                    short_key = "\\".join(key.split("\\")[-2:])
                    reporter.finding(
                        "HIGH",
                        f"Suspicious autorun in {short_key}: {name}",
                        f"Registry key '{key}\\{name}' launches from a suspicious path: {val}",
                        f"Investigate and remove if unexpected: "
                        f"Remove-ItemProperty -Path '{key}' -Name '{name}'",
                    )
        except Exception:
            pass


def _check_windows_temp_executables(reporter):
    """Flag executable files in Windows temp directories (common malware staging)."""
    temp_dirs = []
    for env in ("TEMP", "TMP"):
        d = os.environ.get(env, "")
        if d and os.path.isdir(d):
            temp_dirs.append(d)
    if os.path.isdir(r"C:\Windows\Temp"):
        temp_dirs.append(r"C:\Windows\Temp")

    found = []
    seen: set = set()
    for d in temp_dirs:
        try:
            for entry in os.scandir(d):
                if entry.path in seen or not entry.is_file(follow_symlinks=False):
                    continue
                seen.add(entry.path)
                if os.path.splitext(entry.name)[1].lower() not in _WIN_EXEC_EXTS:
                    continue
                try:
                    if (time.time() - entry.stat().st_mtime) / 86400 <= 30:
                        found.append(entry.path)
                except OSError:
                    pass
        except OSError:
            pass

    for path in found[:20]:
        reporter.finding(
            "HIGH",
            f"Executable in temp directory: {os.path.basename(path)}",
            f"'{path}' is an executable in a temp directory — a common malware staging location.",
            f"Investigate: Get-Item '{path}'; remove if unexpected.",
            fix_cmds=[f"Remove-Item -Path '{path}' -Force -ErrorAction SilentlyContinue"],
        )
    return len(found)


def _check_windows_suspicious_procs(reporter):
    """Flag processes running from temp or public directories on Windows."""
    suspicious_roots = [r"c:\windows\temp", r"c:\users\public"]
    for env in ("TEMP", "TMP"):
        d = os.environ.get(env, "")
        if d:
            suspicious_roots.append(d.lower())

    out, rc = _ps(
        "Get-Process | Where-Object {$_.Path} | Select-Object Name,Id,Path | ConvertTo-Json"
    )
    if rc != 0 or not out.strip():
        return 0
    found = 0
    try:
        procs = json.loads(out)
        if isinstance(procs, dict):
            procs = [procs]
        for p in procs:
            path = (p.get("Path") or "").lower()
            if not path:
                continue
            for root in suspicious_roots:
                if root and path.startswith(root):
                    reporter.finding(
                        "HIGH",
                        f"Process running from temp/public dir: {p.get('Name', '?')} "
                        f"(PID {p.get('Id', '?')})",
                        f"Process is running from a suspicious directory: {p.get('Path')}. "
                        "Legitimate software almost never runs from temp locations.",
                        f"Investigate: Get-Process -Id {p.get('Id', 0)} | Select-Object *",
                    )
                    found += 1
                    break
    except Exception:
        pass
    return found


def _win_third_party_av() -> list:
    """Return names of enabled third-party AV products from SecurityCenter2.

    productState bit 0x1000 in the second byte == 'on'. When Norton /
    Bitdefender / etc. is active, Windows *disables Defender by design* —
    flagging that as CRITICAL was the app's worst false positive.
    """
    out, rc = _ps(
        "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct "
        "-ErrorAction SilentlyContinue | Select-Object displayName,productState | ConvertTo-Json"
    )
    if rc != 0 or not out.strip():
        return []
    try:
        prods = json.loads(out)
    except Exception:
        return []
    if prods is None:                 # PowerShell emits literal "null"
        return []
    if isinstance(prods, dict):
        prods = [prods]
    active = []
    for p in prods:
        name  = p.get("displayName") or ""
        state = p.get("productState") or 0
        try:
            enabled = bool(int(state) & 0x1000)   # 0x1000 nibble == 'on'
        except (TypeError, ValueError):
            enabled = False
        low = name.lower()
        # NB: "Bitdefender" contains the substring "defender" — match the
        # *Microsoft* product specifically so third-party AVs aren't excluded.
        is_ms_defender = "windows defender" in low or "microsoft defender" in low
        if enabled and not is_ms_defender:
            active.append(name)
    return active


def _check_malware_windows(reporter):
    reporter.begin("MALWARE SCAN (Windows Defender + heuristic indicators)")
    third_party = _win_third_party_av()
    # Check Defender status
    out, rc = _ps("Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge | ConvertTo-Json")
    status = {}
    if rc == 0 and out.strip():
        try:
            status = json.loads(out)
        except Exception:
            status = {}
    if not status:
        if third_party:
            reporter.ok(f"Third-party antivirus active: {', '.join(third_party)}")
        else:
            reporter.error("Could not query Windows Defender status")
            reporter.end()
            return
    if status and not status.get("AntivirusEnabled"):
        if third_party:
            reporter.ok(
                f"Windows Defender is standing down because {', '.join(third_party)} "
                "is the active antivirus — this is normal."
            )
        else:
            reporter.finding("CRITICAL", "No active antivirus protection",
                             "Windows Defender is disabled and no third-party antivirus is registered. "
                             "Malware runs unchecked.",
                             "Enable Defender: Windows Security → Virus & threat protection")
    if status and status.get("AntivirusEnabled") and not status.get("RealTimeProtectionEnabled") and not third_party:
        reporter.finding("HIGH", "Windows Defender real-time protection is off",
                         "Without real-time protection, threats aren't caught on access.",
                         "Enable: Set-MpPreference -DisableRealtimeMonitoring $false",
                         fix_cmds=["Set-MpPreference -DisableRealtimeMonitoring $false"])
    sig_age = status.get("AntivirusSignatureAge", 0) or 0
    if status.get("AntivirusEnabled") and sig_age > 7:
        reporter.finding("MEDIUM", f"Defender signatures are {sig_age} day(s) old",
                         "Outdated signatures miss recent malware.",
                         "Update: Update-MpSignature",
                         fix_cmds=["Update-MpSignature"])
    # Active threats only. Get-MpThreatDetection returns *historical* detections
    # too — already-quarantined items were being reported as 'Active threat'.
    out2, rc2 = _ps(
        "Get-MpThreat -ErrorAction SilentlyContinue | Where-Object { $_.IsActive } | "
        "Select-Object ThreatName,SeverityID | ConvertTo-Json"
    )
    if rc2 == 0 and out2.strip() and out2.strip().lower() != "null":
        try:
            threats = json.loads(out2)
            if isinstance(threats, dict):
                threats = [threats]
            for t in threats[:10]:
                reporter.finding("CRITICAL", f"Active threat detected: {t.get('ThreatName','?')}",
                                 f"Windows Defender reports {t.get('ThreatName','?')} as currently active (not yet remediated).",
                                 "Open Windows Security → Virus & threat protection → Current threats")
        except Exception:
            pass

    # Heuristic indicators (equivalent to the Linux ClamAV + heuristic checks)
    _check_windows_registry_persistence(reporter)
    _check_windows_temp_executables(reporter)
    _check_windows_suspicious_procs(reporter)

    reporter.end("Windows Defender + heuristic scan complete.")


_AV_CLAMAV_PATHS  = ["/tmp", "/var/tmp", "/dev/shm", "/home", "/root", "/etc"]
_AV_TEMP_DIRS     = ["/tmp", "/var/tmp", "/dev/shm"]
_AV_SCRIPT_DIRS   = [
    "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
    "/etc/cron.monthly", "/etc/cron.weekly",
    "/etc/profile.d", "/etc/init.d",
    "/tmp", "/var/tmp", "/dev/shm",
    "/var/www",
]

# Known-bad byte patterns found in shells, webshells, and stagers.
# Using bytes regexes so we can scan both text and binary files without
# decoding — avoids UnicodeDecodeError and catches obfuscated payloads.
_AV_PATTERNS = [
    (rb"bash\s+-i\s+>&\s*/dev/tcp/",                     "reverse shell (bash/TCP)"),
    (rb"python[23]?\s*-c\s*.{0,20}import\s+socket",      "reverse shell (Python socket)"),
    (rb"perl\s*-e\s*.{0,10}socket",                      "reverse shell (Perl socket)"),
    (rb"curl\s.{0,120}\|\s*(?:ba)?sh",                   "download-execute (curl|sh)"),
    (rb"wget\s.{0,120}-O\s*-\s*\|",                      "download-execute (wget|-)"),
    (rb"eval\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)\s*\[","PHP webshell (eval injection)"),
    (rb"passthru\s*\(\s*\$_(?:POST|GET|REQUEST)\s*\[",   "PHP webshell (passthru)"),
    (rb"eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13)","PHP obfuscated eval"),
    (rb"(?:^|\s)(?:nc|ncat)\s+-[elEL]",                  "netcat listener"),
    (rb"/bin/(?:ba)?sh\s*-[ipc]\s*>?&?\s*/dev/",         "shell redirect to device"),
]
_AV_PATTERN_RE = [
    (re.compile(pat, re.IGNORECASE | re.DOTALL), name) for pat, name in _AV_PATTERNS
]

_AV_CLAMAV_DB_DIRS = ["/var/lib/clamav"]
_AV_MAX_FILE_BYTES = 524_288  # 512 KB — skip larger files in pattern scan
_AV_SCRIPT_EXTS   = frozenset({
    ".sh", ".bash", ".zsh", ".ksh", ".csh",
    ".py", ".pl", ".rb", ".php", ".lua",
})


def _av_clamav_db_age_days():
    """Return age of newest ClamAV .cvd/.cld in days, or None if not found."""
    for db_dir in _AV_CLAMAV_DB_DIRS:
        if not os.path.isdir(db_dir):
            continue
        try:
            mtimes = [
                os.path.getmtime(os.path.join(db_dir, f))
                for f in os.listdir(db_dir)
                if f.endswith((".cvd", ".cld"))
            ]
            if mtimes:
                return (time.time() - max(mtimes)) / 86400
        except OSError:
            pass
    return None


def _av_run_clamav(reporter, paths):
    """Run clamscan; report findings. Returns count of infected files."""
    clamscan = shutil.which("clamscan")
    if not clamscan:
        if _OS == "Darwin":
            install_hint = "brew install clamav && sudo freshclam"
        else:
            install_hint = "sudo apt-get install clamav && sudo freshclam"
        reporter.info(
            f"ClamAV not installed — signature scan skipped. Install: {install_hint}"
        )
        return 0

    age = _av_clamav_db_age_days()
    if age is not None and age > 7:
        reporter.info(
            f"ClamAV virus database is {age:.0f} days old — "
            "run: sudo freshclam"
        )

    existing = [p for p in paths if os.path.exists(p)]
    if not existing:
        return 0

    reporter.info(f"ClamAV: scanning {', '.join(existing)}…")
    try:
        result = subprocess.run(
            ["clamscan", "--recursive", "--infected", "--no-summary", *existing],
            capture_output=True, text=True, timeout=300,
        )
    except subprocess.TimeoutExpired:
        reporter.error("ClamAV scan timed out (300 s) — try scanning fewer paths.")
        return 0
    except OSError as e:
        reporter.error(f"ClamAV failed to run: {e}")
        return 0

    infected = []
    for line in result.stdout.splitlines():
        if ": " in line and line.rstrip().endswith("FOUND"):
            fpath, sig = line.rsplit(": ", 1)
            infected.append((fpath.strip(), sig.replace(" FOUND", "").strip()))

    for fpath, sig in infected:
        safe = shlex.quote(fpath)
        reporter.finding(
            "CRITICAL",
            f"Malware detected: {sig}",
            f"ClamAV identified '{fpath}' as a known malware signature ({sig}).",
            f"Quarantine immediately: sudo mv {safe} /var/quarantine/",
            fix_cmds=[
                "mkdir -p /var/quarantine",
                f"mv {safe} /var/quarantine/",
            ],
        )

    if not infected:
        reporter.ok(f"ClamAV: clean — {len(existing)} path(s) scanned.")
    return len(infected)


_ELF_MAGIC = b"\x7fELF"
# Mach-O magics (32/64-bit, both endiannesses, plus universal/fat binaries)
_MACHO_MAGICS = frozenset({
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
})
_SHEBANG   = b"#!"


def _av_check_temp_executables(reporter, temp_dirs=None):
    """Flag executable binaries and scripts in temp directories."""
    found = []  # list of (path, kind)
    for d in (temp_dirs or _AV_TEMP_DIRS):
        if not os.path.isdir(d):
            continue
        try:
            for root, _dirs, files in os.walk(d, followlinks=False):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        if not (os.stat(fpath).st_mode & 0o111):
                            continue
                        if not os.path.isfile(fpath):
                            continue
                        with open(fpath, "rb") as fh:
                            magic = fh.read(4)
                        if magic[:4] == _ELF_MAGIC:
                            found.append((fpath, "ELF binary"))
                        elif magic[:4] in _MACHO_MAGICS:
                            found.append((fpath, "Mach-O binary"))
                        elif magic[:2] == _SHEBANG:
                            found.append((fpath, "script"))
                    except OSError:
                        pass
        except OSError:
            pass

    for fpath, kind in found:
        safe = shlex.quote(fpath)
        reporter.finding(
            "HIGH",
            f"Executable {kind} in temp directory: {os.path.basename(fpath)}",
            f"'{fpath}' is a {kind} in a temp directory. Legitimate software almost never "
            "places executables in /tmp or /dev/shm — this is a common malware staging area.",
            f"Investigate: file {safe}; remove if unexpected.",
            fix_cmds=[f"rm -f {safe}"],
        )
    return len(found)


def _av_check_suspicious_procs(reporter):
    """Flag processes running from deleted or temp-dir executables."""
    if _OS != "Linux":
        return 0
    found = []
    try:
        for entry in os.scandir("/proc"):
            if not entry.name.isdigit():
                continue
            pid = entry.name
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
            except OSError:
                continue
            is_deleted = "(deleted)" in exe
            is_tmp     = any(exe.startswith(d + "/") for d in _AV_TEMP_DIRS)
            if not (is_deleted or is_tmp):
                continue
            try:
                with open(f"/proc/{pid}/comm") as fh:
                    comm = fh.read().strip()
            except OSError:
                comm = f"pid-{pid}"
            found.append((pid, comm, exe, is_deleted))
    except OSError:
        pass

    for pid, comm, exe, is_deleted in found:
        sev = "CRITICAL" if is_tmp else "HIGH"
        reason = (
            "running from a deleted file (in-place replacement or cover-up)"
            if is_deleted
            else f"running from {'/'.join(exe.split('/')[:3])} (common malware staging area)"
        )
        safe_exe = shlex.quote(exe.replace(" (deleted)", ""))
        # Guard: only kill if /proc/{pid}/exe still resolves to the same path
        kill_cmd = (
            f"[ -L /proc/{pid}/exe ] && "
            f"kill -9 {pid} && echo 'killed {pid} ({comm})' "
            f"|| echo 'PID {pid} gone or changed — skipped'"
        )
        reporter.finding(
            sev,
            f"Suspicious process: '{comm}' (PID {pid})",
            f"Process {pid} ({comm}) is {reason}. Executable path: {exe}.",
            f"Inspect: sudo ls -la /proc/{pid}/exe; sudo cat /proc/{pid}/cmdline",
            fix_cmds=[kill_cmd],
        )
    return len(found)


def _av_check_ld_preload(reporter):
    """Check /etc/ld.so.preload — a classic rootkit injection point."""
    path = "/etc/ld.so.preload"
    if not os.path.exists(path):
        return 0
    try:
        with open(path) as fh:
            content = fh.read().strip()
    except OSError:
        return 0
    if not content:
        return 0
    reporter.finding(
        "CRITICAL",
        "/etc/ld.so.preload exists with content",
        f"/etc/ld.so.preload forces a shared library into every process on the system. "
        f"Contents: {content[:200]}. This is a textbook rootkit persistence technique.",
        "Inspect the listed library. If unexpected, the system may be fully compromised — "
        "consider restoring from a clean backup.",
        fix_cmds=[
            "cp /etc/ld.so.preload /etc/ld.so.preload.bak",
            "> /etc/ld.so.preload",
            "ldconfig",
        ],
    )
    return 1


_AV_TEMP_DIR_SET = frozenset(_AV_TEMP_DIRS)


def _av_scan_scripts(reporter, script_dirs=None):
    """Scan scripts in high-risk dirs for known-bad patterns."""
    hits = []
    seen = set()
    for base in (script_dirs or _AV_SCRIPT_DIRS):
        if not os.path.exists(base):
            continue
        in_temp = base in _AV_TEMP_DIR_SET
        if os.path.isfile(base):
            walk_iter = [("", [], [base])]
        else:
            walk_iter = os.walk(base, followlinks=False)
        for root, _dirs, files in walk_iter:
            for fname in files:
                fpath = os.path.join(root, fname) if root else fname
                if fpath in seen:
                    continue
                seen.add(fpath)
                try:
                    st = os.stat(fpath)
                    if st.st_size > _AV_MAX_FILE_BYTES:
                        continue
                    # In temp dirs only scan files that look like actual scripts
                    # (shebang or known extension) to avoid false positives on
                    # arbitrary data files dropped by build systems or CI runners.
                    if in_temp:
                        ext = os.path.splitext(fname)[1].lower()
                        if ext not in _AV_SCRIPT_EXTS:
                            with open(fpath, "rb") as fh:
                                if fh.read(2) != b"#!":
                                    continue
                            # re-open for full read below
                    with open(fpath, "rb") as fh:
                        content = fh.read()
                    for pattern_re, name in _AV_PATTERN_RE:
                        if pattern_re.search(content):
                            hits.append((fpath, name))
                            break
                except OSError:
                    pass

    for fpath, name in hits:
        safe = shlex.quote(fpath)
        reporter.finding(
            "HIGH",
            f"Suspicious pattern in {os.path.basename(fpath)}: {name}",
            f"'{fpath}' contains a pattern associated with malware or backdoors ({name}).",
            f"Review immediately: cat {safe}",
            fix_cmds=[
                "mkdir -p /var/quarantine",
                f"mv {safe} /var/quarantine/",
            ],
        )
    return len(hits)


# ── macOS malware checks ────────────────────────────────────────────────────────

_MAC_AV_TEMP_DIRS   = ["/tmp", "/var/tmp", "/private/tmp"]
_MAC_AV_SCAN_DIRS   = [os.path.expanduser("~"), "/private/tmp", "/Users/Shared"]
_MAC_LAUNCHD_DIRS   = [
    os.path.expanduser("~/Library/LaunchAgents"),
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
]
# Apple's own agents live in /System/Library — anything there is SIP-protected.
_MAC_PLIST_SUSPECT_RE = re.compile(
    rb"(?:/tmp/|/var/tmp/|/private/tmp/|/Users/Shared/\.|curl\s|nc\s+-|bash\s+-i|osascript\s+-e|"
    rb"base64\s+(?:-d|--decode)|python[23]?\s+-c)",
    re.IGNORECASE,
)


def _check_gatekeeper_macos(reporter) -> int:
    """Gatekeeper blocks unsigned/unnotarized apps. Off = anything runs."""
    try:
        r = subprocess.run(["spctl", "--status"], capture_output=True,
                           text=True, errors="replace", timeout=10)
        if "disabled" in (r.stdout + r.stderr).lower():
            reporter.finding(
                "HIGH", "Gatekeeper is disabled",
                "With Gatekeeper off, unsigned and unnotarized apps launch without any check — "
                "the single most common way Mac malware gets installed.",
                "Re-enable: sudo spctl --master-enable",
                fix_cmds=["sudo spctl --master-enable"],
            )
            return 1
    except (OSError, subprocess.TimeoutExpired):
        pass
    return 0


def _check_xprotect_macos(reporter) -> int:
    """XProtect is macOS's built-in signature AV. Verify it's present/recent."""
    candidates = [
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
        "/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
    ]
    for p in candidates:
        if os.path.exists(p):
            try:
                age_days = (time.time() - os.path.getmtime(p)) / 86400
            except OSError:
                return 0
            if age_days > 90:
                reporter.finding(
                    "MEDIUM", f"XProtect signatures are {int(age_days)} days old",
                    "macOS's built-in malware signatures haven't updated in months — "
                    "background security updates may be disabled.",
                    "System Settings → General → Software Update → enable "
                    "'Install Security Responses and system files'.",
                )
                return 1
            return 0
    reporter.finding(
        "MEDIUM", "XProtect bundle not found",
        "Could not locate macOS's built-in malware scanner — unusual on a healthy system.",
        "Run Software Update; if it persists, consider reinstalling macOS.",
    )
    return 1


def _check_launchd_persistence_macos(reporter) -> int:
    """Scan LaunchAgents/Daemons plists for malware-style persistence."""
    n = 0
    for d in _MAC_LAUNCHD_DIRS:
        if not os.path.isdir(d):
            continue
        try:
            entries = sorted(os.listdir(d))
        except OSError:
            continue
        for name in entries:
            if not name.endswith(".plist"):
                continue
            path = os.path.join(d, name)
            try:
                if os.path.getsize(path) > 262_144:
                    continue
                with open(path, "rb") as fh:
                    blob = fh.read()
            except OSError:
                continue
            m = _MAC_PLIST_SUSPECT_RE.search(blob)
            if m:
                snippet = m.group(0).decode("utf-8", "replace")
                reporter.finding(
                    "HIGH", f"Suspicious launchd persistence: {name}",
                    f"{path} auto-runs at login/boot and references '{snippet}' — "
                    "temp-directory binaries and inline shells are classic Mac malware persistence.",
                    f"Inspect it: plutil -p '{path}' — if unrecognized, remove and run: "
                    f"launchctl bootout gui/$(id -u) '{path}'",
                )
                n += 1
    return n


def _check_malware_macos(reporter, clamav_paths=None):
    reporter.begin("MALWARE SCAN (macOS)",
                   "Gatekeeper + XProtect + launchd persistence + heuristics")
    n  = _check_gatekeeper_macos(reporter)
    n += _check_xprotect_macos(reporter)
    n += _check_launchd_persistence_macos(reporter)
    # ClamAV if installed (brew install clamav) — scan macOS paths, not /home
    n += _av_run_clamav(reporter, clamav_paths or _MAC_AV_SCAN_DIRS)
    n += _av_check_temp_executables(reporter, temp_dirs=_MAC_AV_TEMP_DIRS)
    n += _av_check_suspicious_procs(reporter)
    n += _av_scan_scripts(reporter, script_dirs=[
        os.path.expanduser("~/Library/LaunchAgents"),
        "/private/tmp", "/var/tmp", "/Users/Shared",
    ])
    if n == 0:
        reporter.ok("No malware indicators found — Gatekeeper and XProtect look healthy.")
    reporter.end(
        f"{n} malware indicator(s) — investigate immediately." if n else None
    )


def check_malware(reporter, clamav_paths=None):
    if _OS == "Windows":
        _check_malware_windows(reporter)
        return
    if _OS == "Darwin":
        _check_malware_macos(reporter, clamav_paths)
        return

    reporter.begin("MALWARE SCAN", "ClamAV signatures + heuristic indicators")

    n  = _av_run_clamav(reporter, clamav_paths or _AV_CLAMAV_PATHS)
    n += _av_check_temp_executables(reporter)
    n += _av_check_suspicious_procs(reporter)
    n += _av_check_ld_preload(reporter)
    n += _av_scan_scripts(reporter)

    if n == 0:
        reporter.ok("No malware indicators found.")
    reporter.end(
        f"{n} malware indicator(s) — investigate immediately." if n else None
    )


# ── Package update check ───────────────────────────────────────────────────────

def _check_packages_macos(reporter):
    reporter.begin("PACKAGE UPDATES (Homebrew)")
    brew = shutil.which("brew")
    if not brew:
        reporter.ok("Homebrew not installed — skipping package check")
        return
    try:
        r = subprocess.run([brew, "outdated", "--quiet"],
                           capture_output=True, text=True, timeout=60)
        outdated = [l.strip() for l in r.stdout.splitlines() if l.strip()]
    except (OSError, subprocess.TimeoutExpired) as e:
        reporter.error(f"brew outdated failed: {e}")
        return
    # macOS Software Update
    try:
        r2 = subprocess.run(["softwareupdate", "--list"],
                            capture_output=True, text=True, timeout=60)
        sw_updates = [l for l in r2.stdout.splitlines() if "* " in l]
    except (OSError, subprocess.TimeoutExpired):
        sw_updates = []
    if outdated:
        reporter.finding(
            "MEDIUM", f"{len(outdated)} outdated Homebrew package(s)",
            "Outdated packages may contain known vulnerabilities.",
            "Run: brew upgrade",
        )
    if sw_updates:
        reporter.finding(
            "HIGH", f"{len(sw_updates)} macOS software update(s) available",
            "System updates often include security patches.",
            "Run: sudo softwareupdate --install --all",
        )
    if not outdated and not sw_updates:
        reporter.ok("All Homebrew packages and macOS software up to date")
    reporter.end()


def _check_packages_windows(reporter):
    reporter.begin("PACKAGE UPDATES (Windows)")
    # Windows Update pending (best-effort; PSWindowsUpdate module may not be installed)
    wu_out, wu_rc = _ps(
        "Get-WindowsUpdate -ErrorAction SilentlyContinue 2>$null "
        "| Measure-Object | Select-Object Count | ConvertTo-Json"
    )
    if wu_rc == 0 and wu_out.strip():
        try:
            wu_count = json.loads(wu_out).get("Count", 0) or 0
            if wu_count > 0:
                reporter.finding(
                    "HIGH", f"{wu_count} Windows Update(s) pending",
                    "Pending Windows Updates may include critical security patches.",
                    "Open Windows Update: Start → Settings → Windows Update → Check for updates",
                )
        except Exception:
            pass
    # Winget upgrades. NOTE: `winget upgrade --list` is an INVALID flag on
    # modern winget (>= 1.4) — the command errored and the check silently
    # reported "no upgrades" on every machine.
    winget = shutil.which("winget")
    if winget:
        try:
            r = subprocess.run(
                [winget, "upgrade", "--include-unknown",
                 "--accept-source-agreements", "--disable-interactivity"],
                capture_output=True, text=True, errors="replace",
                timeout=90, creationflags=_NO_WINDOW,
            )
            n = _parse_winget_upgrade_count(r.stdout)
            if n > 0:
                reporter.finding(
                    "MEDIUM", f"{n} winget package upgrade(s) available",
                    "Outdated packages may contain known vulnerabilities.",
                    "Run: winget upgrade --all",
                )
                reporter.end()
                return
        except (OSError, subprocess.TimeoutExpired):
            pass
    reporter.ok("No pending package upgrades detected via winget")
    reporter.end()


def _parse_winget_upgrade_count(stdout: str) -> int:
    """Robustly count upgradeable packages from `winget upgrade` output.

    Prefers the explicit '<N> upgrades available' summary line; falls back to
    counting rows between the '---' header rule and the summary/blank line.
    """
    m = re.search(r"(\d+)\s+upgrades?\s+available", stdout, re.IGNORECASE)
    if m:
        return int(m.group(1))
    lines = stdout.splitlines()
    try:
        sep = next(i for i, l in enumerate(lines) if set(l.strip()) == {"-"} and len(l.strip()) > 10)
    except StopIteration:
        return 0
    count = 0
    for l in lines[sep + 1:]:
        s = l.strip()
        if not s or re.match(r"^\d+\s+upgrades?", s, re.IGNORECASE):
            break
        count += 1
    return count


def _parse_apt_upgradeable(stdout):
    """Return (security_pkgs, other_pkgs) lists from `apt list --upgradeable` output."""
    security, other = [], []
    for line in stdout.splitlines():
        if not line or line.startswith("Listing"):
            continue
        pkg = line.split("/")[0]
        if not pkg:
            continue
        if "/security" in line or "-security" in line:
            security.append(pkg)
        else:
            other.append(pkg)
    return security, other


def _parse_dnf_check_update(stdout):
    """Return (security_pkgs, other_pkgs) from `dnf check-update` output.

    Lines look like:
        bash.x86_64    5.1.8-6.el9_1    baseos
        kernel.x86_64  5.14.0-362.el9   security
    We treat anything with 'security' in the repo column as a security update.
    """
    security, other = [], []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("Last metadata") or line.startswith("Obsoleting"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        pkg = parts[0]
        repo = parts[2] if len(parts) >= 3 else ""
        if "security" in repo.lower():
            security.append(pkg)
        else:
            other.append(pkg)
    return security, other


def check_packages(reporter):
    if _OS == "Darwin":
        _check_packages_macos(reporter)
        return
    if _OS == "Windows":
        _check_packages_windows(reporter)
        return

    reporter.begin("PACKAGE UPDATES", "checking for outdated system packages")

    apt_path = shutil.which("apt")
    dnf_path = shutil.which("dnf") or shutil.which("yum")

    if not apt_path and not dnf_path:
        reporter.info("No supported package manager found (apt/dnf/yum).")
        reporter.end()
        return

    try:
        if apt_path:
            result = subprocess.run(
                [apt_path, "list", "--upgradeable"],
                capture_output=True, text=True, timeout=60,
            )
            security, other = _parse_apt_upgradeable(result.stdout)
        else:
            result = subprocess.run(
                [dnf_path, "check-update", "--quiet"],
                capture_output=True, text=True, timeout=60,
            )
            security, other = _parse_dnf_check_update(result.stdout)
    except subprocess.TimeoutExpired:
        reporter.error("Package check timed out after 60 s.")
        reporter.end()
        return
    except OSError as e:
        reporter.error(f"Could not run package manager: {e}")
        reporter.end()
        return

    if not security and not other:
        reporter.ok("All packages are up to date.")
        reporter.end()
        return

    upgrade_cmd = (
        "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"
        if apt_path else f"{dnf_path} upgrade -y"
    )
    if security:
        preview = ", ".join(security[:5])
        tail = f" (+{len(security) - 5} more)" if len(security) > 5 else ""
        reporter.finding(
            "CRITICAL",
            f"{len(security)} security update(s) pending",
            "Unpatched packages are the most common initial compromise vector.",
            f"Run in a terminal: sudo {upgrade_cmd}",
            packages=f"{preview}{tail}",
        )
    if other:
        reporter.finding(
            "MEDIUM",
            f"{len(other)} non-security update(s) pending",
            "Outdated packages may contain known bugs or CVEs not yet flagged as security.",
            f"Run in a terminal: sudo {upgrade_cmd}",
        )

    total = len(security) + len(other)
    reporter.end(f"{total} package update(s) pending.")


# ── System Cleaner ─────────────────────────────────────────────────────────────

def _dir_size_mb(path):
    """Best-effort recursive directory size in MB; returns 0 on permission error."""
    total = 0
    try:
        for dirpath, _, filenames in os.walk(path):
            for fn in filenames:
                try:
                    total += os.path.getsize(os.path.join(dirpath, fn))
                except OSError:
                    pass
    except OSError:
        pass
    return total // (1024 * 1024)


def _check_system_cleaner_windows(reporter):
    """Identify reclaimable disk space on Windows."""
    reporter.begin("SYSTEM CLEANER", "scanning for reclaimable disk space and system debris")
    found_any = False

    # User temp folder (%TEMP%)
    user_temp = os.environ.get("TEMP") or os.environ.get("TMP", "")
    if user_temp and os.path.isdir(user_temp):
        mb = _dir_size_mb(user_temp)
        if mb >= 100:
            reporter.finding(
                "REVIEW",
                f"User temp folder: {mb} MB reclaimable",
                f"{user_temp} holds {mb} MB of temporary files.",
                f"Run Disk Cleanup or: Remove-Item -Path '{user_temp}\\*' -Recurse -Force",
                fix_cmds=[
                    f"Remove-Item -Path '{user_temp}\\*' -Recurse -Force "
                    "-ErrorAction SilentlyContinue"
                ],
            )
            found_any = True

    # System temp (C:\Windows\Temp)
    sys_temp = r"C:\Windows\Temp"
    if os.path.isdir(sys_temp):
        mb = _dir_size_mb(sys_temp)
        if mb >= 100:
            reporter.finding(
                "REVIEW",
                f"Windows system temp: {mb} MB reclaimable",
                f"{sys_temp} holds {mb} MB of temporary files.",
                r"Run: Remove-Item -Path 'C:\Windows\Temp\*' -Recurse -Force",
                fix_cmds=[
                    r"Remove-Item -Path 'C:\Windows\Temp\*' -Recurse -Force "
                    "-ErrorAction SilentlyContinue"
                ],
            )
            found_any = True

    # Windows Update download cache
    wu_cache = r"C:\Windows\SoftwareDistribution\Download"
    if os.path.isdir(wu_cache):
        mb = _dir_size_mb(wu_cache)
        if mb >= 200:
            reporter.finding(
                "REVIEW",
                f"Windows Update cache: {mb} MB reclaimable",
                f"{wu_cache} holds {mb} MB of downloaded update files that may already be applied.",
                "Stop Windows Update, clear the cache, then restart the service.",
                fix_cmds=[
                    "net stop wuauserv",
                    f"Remove-Item -Path '{wu_cache}\\*' -Recurse -Force "
                    "-ErrorAction SilentlyContinue",
                    "net start wuauserv",
                ],
            )
            found_any = True

    # Crash dumps and minidumps
    crash_dirs = [r"C:\Windows\Minidump"]
    local_appdata = os.environ.get("LOCALAPPDATA", "")
    if local_appdata:
        crash_dirs.append(os.path.join(local_appdata, "CrashDumps"))
    for d in crash_dirs:
        if not os.path.isdir(d):
            continue
        try:
            dumps = [f for f in os.listdir(d) if f.lower().endswith((".dmp", ".mdmp"))]
        except OSError:
            dumps = []
        if dumps:
            mb = _dir_size_mb(d)
            reporter.finding(
                "REVIEW",
                f"{len(dumps)} crash dump(s) in {os.path.basename(d)} ({mb} MB)",
                "Crash/minidump files accumulate after application or system crashes.",
                f"Run: Remove-Item -Path '{d}\\*.dmp' -Force",
                fix_cmds=[
                    f"Remove-Item -Path '{d}\\*.dmp' -Force -ErrorAction SilentlyContinue"
                ],
            )
            found_any = True

    # Recycle Bin size
    out, _ = _ps(
        "(New-Object -ComObject Shell.Application).Namespace(0xa).Items() "
        "| Measure-Object -Property Size -Sum | Select-Object -ExpandProperty Sum"
    )
    try:
        rb_mb = int(out.strip()) // (1024 * 1024)
        if rb_mb >= 100:
            reporter.finding(
                "INFO",
                f"Recycle Bin: {rb_mb} MB",
                f"Recycle Bin contains {rb_mb} MB of deleted files not yet purged.",
                "Empty the Recycle Bin.",
                fix_cmds=["Clear-RecycleBin -Force -ErrorAction SilentlyContinue"],
            )
            found_any = True
    except (ValueError, TypeError):
        pass

    # Delivery Optimization cache (peer-to-peer Windows Update sharing)
    do_cache = (
        r"C:\Windows\ServiceProfiles\NetworkService\AppData\Local"
        r"\Microsoft\Windows\DeliveryOptimization\Cache"
    )
    if os.path.isdir(do_cache):
        mb = _dir_size_mb(do_cache)
        if mb >= 200:
            reporter.finding(
                "REVIEW",
                f"Delivery Optimization cache: {mb} MB",
                "Windows Delivery Optimization stores update downloads for peer sharing — safe to clear.",
                "Run: Delete-DeliveryOptimizationCache -Force",
                fix_cmds=["Delete-DeliveryOptimizationCache -Force -ErrorAction SilentlyContinue"],
            )
            found_any = True

    # Browser + dev caches (shared with all platforms)
    if _cleaner_common_caches(reporter) > 0:
        found_any = True

    if not found_any:
        reporter.ok("System is clean — no significant reclaimable space found.")
    reporter.end()


def check_system_cleaner(reporter):
    """Identify reclaimable disk space: package cache, orphans, old kernels,
    journal bloat, crash reports, temp junk, dpkg debris."""
    if _OS == "Windows":
        _check_system_cleaner_windows(reporter)
        return
    if _OS == "Darwin":
        _check_system_cleaner_macos(reporter)
        return
    reporter.begin("SYSTEM CLEANER", "scanning for reclaimable disk space and system debris")
    import glob as _glob
    import platform as _platform

    found_any = False

    # 1. APT package cache
    if shutil.which("apt-get"):
        mb = _dir_size_mb("/var/cache/apt/archives")
        if mb >= 50:
            reporter.finding(
                "REVIEW",
                f"APT cache: {mb} MB reclaimable",
                f"/var/cache/apt/archives holds {mb} MB of downloaded .deb files.",
                "Run: sudo apt-get clean",
                fix_cmds=["apt-get clean"],
            )
            found_any = True

    # 2. APT autoremovable packages
    if shutil.which("apt-get"):
        try:
            r = subprocess.run(
                ["apt-get", "--dry-run", "autoremove"],
                capture_output=True, text=True, timeout=30,
            )
            lines = [ln for ln in r.stdout.splitlines() if ln.startswith("Remv ")]
            if lines:
                reporter.finding(
                    "REVIEW",
                    f"{len(lines)} orphaned package(s) to remove",
                    "Packages installed as dependencies but no longer needed.",
                    "Run in a terminal: sudo apt-get autoremove -y",
                )
                found_any = True
        except (subprocess.TimeoutExpired, OSError):
            pass

    # 3. DNF autoremovable (non-apt systems)
    dnf = shutil.which("dnf") or shutil.which("yum")
    if dnf and not shutil.which("apt-get"):
        try:
            r = subprocess.run(
                [dnf, "autoremove", "--assumeno"],
                capture_output=True, text=True, timeout=30,
            )
            if "Remove" in r.stdout:
                reporter.finding(
                    "REVIEW",
                    "Orphaned packages to remove",
                    "Packages installed as dependencies but no longer needed.",
                    f"Run in a terminal: sudo {os.path.basename(dnf)} autoremove -y",
                )
                found_any = True
        except (subprocess.TimeoutExpired, OSError):
            pass

    # 4. Old Linux kernels (apt/dpkg systems)
    if shutil.which("dpkg"):
        running_kernel = _platform.release()
        try:
            r = subprocess.run(
                ["dpkg", "--list", "linux-image-*"],
                capture_output=True, text=True, timeout=15,
            )
            old = []
            for line in r.stdout.splitlines():
                if not line.startswith("ii"):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                pkg = parts[1]
                if running_kernel in pkg:
                    continue
                if not re.match(r"linux-image-\d+\.\d+\.\d+", pkg):
                    continue
                old.append(pkg)
            if old:
                pkg_list = " ".join(old)
                reporter.finding(
                    "MEDIUM",
                    f"{len(old)} old kernel image(s) installed",
                    f"Old kernels consume disk space. Running kernel: {running_kernel}.",
                    f"Run in a terminal: sudo apt-get purge {pkg_list}",
                )
                found_any = True
        except (subprocess.TimeoutExpired, OSError):
            pass

    # 5. systemd journal
    if shutil.which("journalctl"):
        try:
            r = subprocess.run(
                ["journalctl", "--disk-usage"],
                capture_output=True, text=True, timeout=10,
            )
            m = re.search(r"take up ([\d.]+)\s*([MG])(?:iB|B)?", r.stdout)
            if m:
                val = float(m.group(1))
                unit = m.group(2)
                mb_val = val * 1024 if unit == "G" else val
                if mb_val >= 200:
                    reporter.finding(
                        "REVIEW",
                        f"systemd journal: {m.group(1)} {unit}B on disk",
                        "Journal logs accumulate over time. Vacuum to 200 MB.",
                        "Run: sudo journalctl --vacuum-size=200M",
                        fix_cmds=["journalctl --vacuum-size=200M"],
                    )
                    found_any = True
        except (subprocess.TimeoutExpired, OSError):
            pass

    # 6. Crash reports
    crash_dir = "/var/crash"
    try:
        crashes = [f for f in os.listdir(crash_dir)
                   if os.path.isfile(os.path.join(crash_dir, f))]
    except OSError:
        crashes = []
    if crashes:
        mb = _dir_size_mb(crash_dir)
        reporter.finding(
            "REVIEW",
            f"{len(crashes)} crash report(s) in /var/crash ({mb} MB)",
            "Crash core dumps from failed applications accumulate in /var/crash.",
            "Run: sudo rm -rf /var/crash/*",
            fix_cmds=["rm -rf /var/crash/*"],
        )
        found_any = True

    # 7. dpkg config debris (.dpkg-old, .dpkg-dist, .dpkg-new)
    debris = []
    for pattern in [
        "/etc/**/*.dpkg-old", "/etc/**/*.dpkg-dist",
        "/etc/**/*.dpkg-new", "/etc/**/*.ucf-old", "/etc/**/*.ucf-dist",
    ]:
        debris.extend(_glob.glob(pattern, recursive=True))
    if debris:
        cmds = [f"rm -f {shlex.quote(f)}" for f in sorted(debris)[:25]]
        reporter.finding(
            "INFO",
            f"{len(debris)} old config file(s) (.dpkg-old / .dpkg-dist)",
            "Leftover config debris from package upgrades clutter /etc.",
            "Delete *.dpkg-old and *.dpkg-dist files in /etc.",
            fix_cmds=cmds,
        )
        found_any = True

    # 8. Large stale temp files (> 10 MB, not modified in 7+ days)
    old_tmp = []
    for tdir in ("/tmp", "/var/tmp"):
        try:
            for entry in os.scandir(tdir):
                try:
                    stat = entry.stat()
                    age_days = (time.time() - stat.st_mtime) / 86400
                    size_mb = stat.st_size // (1024 * 1024)
                    if age_days > 7 and size_mb >= 10:
                        old_tmp.append((entry.path, size_mb))
                except OSError:
                    pass
        except OSError:
            pass
    if old_tmp:
        total_mb = sum(s for _, s in old_tmp)
        cmds = [f"rm -rf {shlex.quote(p)}" for p, _ in old_tmp[:15]]
        reporter.finding(
            "INFO",
            f"{len(old_tmp)} large stale temp file(s) ({total_mb} MB)",
            "Files > 10 MB in /tmp or /var/tmp not touched in 7+ days.",
            "Remove old temp files.",
            fix_cmds=cmds,
        )
        found_any = True

    # 9. User thumbnail cache
    thumb_dir = os.path.join(
        os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"),
        "thumbnails",
    )
    if os.path.isdir(thumb_dir):
        mb = _dir_size_mb(thumb_dir)
        if mb >= 20:
            reporter.finding(
                "INFO",
                f"Thumbnail cache: {mb} MB",
                "Desktop thumbnail cache can grow large over time.",
                f"rm -rf {shlex.quote(thumb_dir)}",
                fix_cmds=[f"rm -rf {shlex.quote(thumb_dir)}"],
            )
            found_any = True

    if not found_any:
        found_any = _cleaner_common_caches(reporter) > 0
    else:
        _cleaner_common_caches(reporter)

    if not found_any:
        reporter.ok("System is clean — no significant reclaimable space found.")

    reporter.end()


# ── Cross-platform caches (CCleaner parity) ────────────────────────────────────

def _browser_cache_dirs() -> list:
    """Return (browser_name, cache_dir) pairs per platform."""
    home = os.path.expanduser("~")
    if _OS == "Windows":
        la = os.environ.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local"))
        return [
            ("Chrome",  os.path.join(la, "Google", "Chrome", "User Data", "Default", "Cache")),
            ("Edge",    os.path.join(la, "Microsoft", "Edge", "User Data", "Default", "Cache")),
            ("Brave",   os.path.join(la, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Cache")),
            ("Firefox", os.path.join(la, "Mozilla", "Firefox", "Profiles")),
        ]
    if _OS == "Darwin":
        c = os.path.join(home, "Library", "Caches")
        return [
            ("Chrome",  os.path.join(c, "Google", "Chrome")),
            ("Edge",    os.path.join(c, "Microsoft Edge")),
            ("Brave",   os.path.join(c, "BraveSoftware")),
            ("Firefox", os.path.join(c, "Firefox")),
            ("Safari",  os.path.join(c, "com.apple.Safari")),
        ]
    c = os.environ.get("XDG_CACHE_HOME") or os.path.join(home, ".cache")
    return [
        ("Chrome",   os.path.join(c, "google-chrome")),
        ("Chromium", os.path.join(c, "chromium")),
        ("Brave",    os.path.join(c, "BraveSoftware")),
        ("Firefox",  os.path.join(c, "mozilla")),
    ]


def _dev_cache_dirs() -> list:
    """pip / npm caches — often gigabytes on developer machines."""
    home = os.path.expanduser("~")
    out = []
    if _OS == "Windows":
        la = os.environ.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local"))
        out.append(("pip cache", os.path.join(la, "pip", "cache")))
        out.append(("npm cache", os.path.join(os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming")), "npm-cache")))
    elif _OS == "Darwin":
        out.append(("pip cache", os.path.join(home, "Library", "Caches", "pip")))
        out.append(("npm cache", os.path.join(home, ".npm")))
    else:
        c = os.environ.get("XDG_CACHE_HOME") or os.path.join(home, ".cache")
        out.append(("pip cache", os.path.join(c, "pip")))
        out.append(("npm cache", os.path.join(home, ".npm")))
    return out


def _cleaner_common_caches(reporter) -> int:
    """Browser + developer caches on every platform. Returns finding count.

    Browsers rebuild their caches automatically; we only flag them above
    150 MB so the recommendation is always worth the rebuild cost.
    """
    n = 0
    for name, d in _browser_cache_dirs():
        if not os.path.isdir(d):
            continue
        mb = _dir_size_mb(d)
        if mb >= 150:
            if _OS == "Windows":
                cmd = f'powershell -Command Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "{d}\\*"'
            else:
                cmd = f"rm -rf {shlex.quote(d)}/*"
            reporter.finding(
                "INFO", f"{name} browser cache: {mb} MB",
                f"{name}'s cache at {d} will be rebuilt automatically — safe to clear "
                "(close the browser first).",
                "Clear it from the browser's own settings, or use the fix below.",
                fix_cmds=[cmd],
            )
            n += 1
    for name, d in _dev_cache_dirs():
        if not os.path.isdir(d):
            continue
        mb = _dir_size_mb(d)
        if mb >= 200:
            tool = "pip cache purge" if "pip" in name else "npm cache clean --force"
            reporter.finding(
                "INFO", f"{name}: {mb} MB",
                f"Package-manager download cache at {d}. Packages re-download on demand.",
                f"Run: {tool}",
                fix_cmds=[tool],
            )
            n += 1
    return n


# ── macOS cleaner ───────────────────────────────────────────────────────────────

def _check_system_cleaner_macos(reporter):
    """macOS reclaimable space: user caches, Trash, logs, Xcode debris,
    iOS device backups, Homebrew cache, stale temp files.

    (Previously the Cleaner tab fell through to the Linux apt/dpkg/journalctl
    path on macOS and reported nothing.)
    """
    reporter.begin("SYSTEM CLEANER (macOS)",
                   "scanning for reclaimable disk space and system debris")
    home = os.path.expanduser("~")
    found_any = False

    # 1. User caches (~/Library/Caches) — biggest single win on most Macs
    caches = os.path.join(home, "Library", "Caches")
    mb = _dir_size_mb(caches)
    if mb >= 200:
        reporter.finding(
            "REVIEW", f"User app caches: {mb} MB",
            f"~/Library/Caches holds {mb} MB of per-app cache data. Apps rebuild "
            "their caches automatically; clearing is safe but makes first launches slower.",
            "Review large folders inside ~/Library/Caches and delete the ones you recognize.",
        )
        found_any = True

    # 2. Trash
    trash = os.path.join(home, ".Trash")
    mb = _dir_size_mb(trash)
    if mb >= 100:
        reporter.finding(
            "INFO", f"Trash: {mb} MB",
            "Files in the Trash still occupy disk space until emptied.",
            "Finder → Empty Trash, or use the fix below.",
            fix_cmds=[f"rm -rf {shlex.quote(trash)}/*"],
        )
        found_any = True

    # 3. User logs
    logs = os.path.join(home, "Library", "Logs")
    mb = _dir_size_mb(logs)
    if mb >= 100:
        reporter.finding(
            "INFO", f"User logs: {mb} MB",
            "~/Library/Logs accumulates diagnostic logs apps never clean up.",
            "Safe to clear — apps recreate logs as needed.",
            fix_cmds=[f"rm -rf {shlex.quote(logs)}/*"],
        )
        found_any = True

    # 4. Xcode DerivedData + old simulators (developer machines)
    derived = os.path.join(home, "Library", "Developer", "Xcode", "DerivedData")
    mb = _dir_size_mb(derived)
    if mb >= 500:
        reporter.finding(
            "REVIEW", f"Xcode DerivedData: {mb} MB",
            "Xcode build intermediates — fully regenerated on the next build.",
            "Safe to clear.",
            fix_cmds=[f"rm -rf {shlex.quote(derived)}/*"],
        )
        found_any = True

    # 5. iOS device backups
    backups = os.path.join(home, "Library", "Application Support", "MobileSync", "Backup")
    mb = _dir_size_mb(backups)
    if mb >= 1000:
        reporter.finding(
            "REVIEW", f"iOS device backups: {mb} MB",
            "Old iPhone/iPad backups can occupy tens of GB. Only remove backups "
            "for devices you no longer need to restore.",
            "Manage in: System Settings → General → Storage → iOS Files, "
            "or Finder → device → Manage Backups.",
        )
        found_any = True

    # 6. Homebrew cache
    if shutil.which("brew"):
        try:
            r = subprocess.run(["brew", "cleanup", "--dry-run"],
                               capture_output=True, text=True, errors="replace", timeout=60)
            m = re.search(r"would free approximately ([\d.,]+\s*[KMGT]?B)", r.stdout, re.IGNORECASE)
            freed = m.group(1) if m else None
            if freed or "Would remove" in r.stdout:
                reporter.finding(
                    "INFO",
                    f"Homebrew cleanup would free {freed}" if freed else "Homebrew has removable cache/old versions",
                    "Old formula versions and download cache kept by Homebrew.",
                    "Run: brew cleanup",
                    fix_cmds=["brew cleanup"],
                )
                found_any = True
        except (OSError, subprocess.TimeoutExpired):
            pass

    # 7. Large stale temp files
    old_tmp = []
    for tdir in ("/private/tmp", "/var/tmp"):
        try:
            for entry in os.scandir(tdir):
                try:
                    st = entry.stat()
                    age_days = (time.time() - st.st_mtime) / 86400
                    size_mb  = st.st_size // (1024 * 1024)
                    if age_days > 7 and size_mb >= 10:
                        old_tmp.append((entry.path, size_mb))
                except OSError:
                    pass
        except OSError:
            pass
    if old_tmp:
        total_mb = sum(s for _, s in old_tmp)
        reporter.finding(
            "INFO", f"{len(old_tmp)} large stale temp file(s) ({total_mb} MB)",
            "Files > 10 MB in temp directories not touched in 7+ days.",
            "Remove old temp files.",
            fix_cmds=[f"rm -rf {shlex.quote(p)}" for p, _ in old_tmp[:15]],
        )
        found_any = True

    # 8. Browser + dev caches (shared with all platforms)
    if _cleaner_common_caches(reporter) > 0:
        found_any = True

    if not found_any:
        reporter.ok("System is clean — no significant reclaimable space found.")
    reporter.end()


# ── Startup programs audit ──────────────────────────────────────────────────────

# For the "I want more FPS" user this is the single highest-impact check:
# every auto-start program eats RAM, CPU and boot time forever. We report each
# item separately so fixes are explicit and reversible via snapshots.

_WIN_RUN_KEYS = [
    r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
]

_WIN_STARTUP_SKIP_PROPS = {
    "PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider",
}

_OPTIONAL_STARTUP_RE = re.compile(
    r"(adobe|battle\.net|brave|chrome|discord|dropbox|ea\s*app|epic|"
    r"game|gog|google|helper|launcher|onedrive|origin|overwolf|slack|"
    r"spotify|steam|sync|teams|tray|ubisoft|update|zoom)",
    re.IGNORECASE,
)

_ESSENTIAL_STARTUP_RE = re.compile(
    r"(at-spi|defender|firewall|gnome-keyring|kdeconnect|malware|"
    r"microsoft security|nm-applet|pipewire|polkit|pulseaudio|"
    r"securityhealth|xapp-sn-watcher|xdg-desktop-portal)",
    re.IGNORECASE,
)


def _json_array(stdout: str) -> list:
    try:
        data = json.loads(stdout)
    except Exception:
        return []
    if data is None:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return [data]
    return []


def _startup_hint(name: str, command: str = "") -> str:
    blob = f"{name} {command}"
    if _ESSENTIAL_STARTUP_RE.search(blob):
        return "This looks security/system-adjacent; keep it unless you know exactly why it is there."
    if _OPTIONAL_STARTUP_RE.search(blob):
        return "This looks like a launcher, updater, tray helper, sync client, or overlay."
    return "Review whether this needs to run immediately after login."


def _check_startup_windows(reporter):
    n = 0
    for key in _WIN_RUN_KEYS:
        out, rc = _ps(
            f"Get-ItemProperty -Path {_ps_quote(key)} -ErrorAction SilentlyContinue | "
            "Select-Object -Property * -ExcludeProperty PS* | ConvertTo-Json"
        )
        if rc != 0 or not out.strip():
            continue
        for props in _json_array(out):
            for name, val in props.items():
                if name in _WIN_STARTUP_SKIP_PROPS or str(name).startswith("PS"):
                    continue
                if not isinstance(val, str) or not val.strip():
                    continue
                cmd = (
                    f"Remove-ItemProperty -Path {_ps_quote(key)} "
                    f"-Name {_ps_quote(name)} -ErrorAction SilentlyContinue"
                )
                reporter.finding(
                    "REVIEW", f"Startup app: {name}",
                    f"{name} launches at sign-in from {key}. "
                    f"{_startup_hint(name, val)} Command: {_truncate(val)}",
                    "Disable this startup entry if you do not need it before launching a game.",
                    fix_cmds=[cmd],
                    source=key, command=val,
                )
                n += 1

    for env, label in (("APPDATA", "user Startup folder"),
                       ("PROGRAMDATA", "all-users Startup folder")):
        base = os.environ.get(env)
        if not base:
            continue
        folder = os.path.join(
            base, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
        try:
            entries = sorted(os.scandir(folder), key=lambda e: e.name.lower())
        except OSError:
            continue
        dest_root = os.path.join(
            os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"),
            "ExposureChecker", "DisabledStartup",
        )
        if env == "PROGRAMDATA":
            dest_root = os.path.join(base, "ExposureChecker", "DisabledStartup")
        for entry in entries:
            if entry.name.lower() == "desktop.ini":
                continue
            dst = os.path.join(dest_root, entry.name)
            cmd = (
                f"New-Item -ItemType Directory -Force -Path {_ps_quote(dest_root)} | Out-Null; "
                f"Move-Item -LiteralPath {_ps_quote(entry.path)} "
                f"-Destination {_ps_quote(dst)} -Force"
            )
            reporter.finding(
                "REVIEW", f"Startup folder item: {entry.name}",
                f"{entry.name} starts from the {label}. "
                f"{_startup_hint(entry.name, entry.path)}",
                "Move it out of the Startup folder if it is not needed at login.",
                fix_cmds=[cmd],
                source=folder, command=entry.path,
            )
            n += 1

    out, rc = _ps(
        "$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | "
        "Where-Object { $_.State -ne 'Disabled' -and "
        "$_.TaskPath -notlike '\\Microsoft\\Windows\\*' -and "
        "($_.Triggers | Where-Object { $_.CimClass.CimClassName -match 'Logon|Boot' }) }; "
        "$tasks | Select-Object TaskName,TaskPath,State | ConvertTo-Json",
        timeout=45,
    )
    if rc == 0 and out.strip():
        for task in _json_array(out):
            name = task.get("TaskName") or ""
            path = task.get("TaskPath") or "\\"
            if not name:
                continue
            cmd = (
                f"Disable-ScheduledTask -TaskPath {_ps_quote(path)} "
                f"-TaskName {_ps_quote(name)}"
            )
            reporter.finding(
                "REVIEW", f"Startup scheduled task: {path}{name}",
                "This non-Microsoft scheduled task runs at boot or login. "
                f"{_startup_hint(name, path)}",
                "Disable the task if it is a helper/updater you do not need while gaming.",
                fix_cmds=[cmd],
                source="Task Scheduler",
            )
            n += 1

    if n == 0:
        reporter.ok("No third-party startup programs found")
    return n


def _osascript_quote(value: str) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _mac_disable_launch_item_cmd(path: str, scope: str) -> str:
    home = os.path.expanduser("~")
    if path.startswith(home):
        dest_dir = os.path.join(home, "Library", "Application Support",
                                "Exposure Checker", "Disabled LaunchItems")
    else:
        dest_dir = "/Library/Application Support/Exposure Checker/Disabled LaunchItems"
    dest = os.path.join(dest_dir, os.path.basename(path))
    domain = "system" if scope == "system daemon" else "gui/$(id -u)"
    return (
        f"mkdir -p {_shell_quote(dest_dir)}; "
        f"/bin/launchctl bootout {domain} {_shell_quote(path)} >/dev/null 2>&1 || true; "
        f"mv -f {_shell_quote(path)} {_shell_quote(dest)}"
    )


def _check_startup_macos(reporter):
    home = os.path.expanduser("~")
    n = 0
    for d, scope in [
        (os.path.join(home, "Library", "LaunchAgents"), "user agent"),
        ("/Library/LaunchAgents", "system agent"),
        ("/Library/LaunchDaemons", "system daemon"),
    ]:
        try:
            entries = sorted(os.listdir(d))
        except OSError:
            continue
        for entry in entries:
            if not entry.endswith(".plist") or entry.startswith("com.apple."):
                continue
            path = os.path.join(d, entry)
            label = entry[:-6]
            reporter.finding(
                "REVIEW", f"Launch item: {label}",
                f"{label} is a {scope} loaded at login or boot from {path}. "
                f"{_startup_hint(label, path)}",
                "Disable it if you do not need this helper running in the background.",
                fix_cmds=[_mac_disable_launch_item_cmd(path, scope)],
                source=path,
            )
            n += 1

    try:
        r = subprocess.run(
            ["osascript", "-e",
             'tell application "System Events" to get the name of every login item'],
            capture_output=True, text=True, errors="replace", timeout=15,
        )
        if r.returncode == 0 and r.stdout.strip():
            for name in [x.strip() for x in r.stdout.strip().split(",") if x.strip()]:
                script = (
                    'tell application "System Events" to delete login item '
                    + _osascript_quote(name)
                )
                reporter.finding(
                    "REVIEW", f"Login item: {name}",
                    f"{name} launches at login. {_startup_hint(name)}",
                    "Remove this login item if it is not needed before gaming.",
                    fix_cmds=[f"osascript -e {_shell_quote(script)}"],
                    source="Login Items",
                )
                n += 1
    except (OSError, subprocess.TimeoutExpired):
        pass

    if n == 0:
        reporter.ok("No third-party startup items found")
    return n


def _desktop_entry_summary(path: str) -> dict:
    out = {
        "name": os.path.basename(path).removesuffix(".desktop"),
        "exec": "",
        "hidden": False,
    }
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                if key == "Name" and val:
                    out["name"] = val.strip()
                elif key == "Exec" and val:
                    out["exec"] = val.strip()
                elif key == "Hidden":
                    out["hidden"] = val.strip().lower() == "true"
    except OSError:
        pass
    return out


def _linux_autostart_dirs() -> list:
    home = os.path.expanduser("~")
    cfg_home = os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
    dirs = [os.path.join(cfg_home, "autostart")]
    for base in (os.environ.get("XDG_CONFIG_DIRS") or "/etc/xdg").split(":"):
        if base:
            dirs.append(os.path.join(base, "autostart"))
    return dirs


def _linux_disable_desktop_cmd(path: str, filename: str, display_name: str,
                               user_entry: bool) -> str:
    home = os.path.expanduser("~")
    cfg_home = os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
    if user_entry:
        dest_dir = os.path.join(cfg_home, "exposure-checker", "disabled-startup")
        dest = os.path.join(dest_dir, filename)
        return (
            f"mkdir -p {_shell_quote(dest_dir)} && "
            f"mv -- {_shell_quote(path)} {_shell_quote(dest)}"
        )
    override_dir = os.path.join(cfg_home, "autostart")
    override = os.path.join(override_dir, filename)
    lines = ["[Desktop Entry]", "Type=Application",
             f"Name={display_name}", "Hidden=true"]
    return (
        f"mkdir -p {_shell_quote(override_dir)} && "
        "printf '%s\\n' " + " ".join(_shell_quote(x) for x in lines)
        + f" > {_shell_quote(override)}"
    )


def _check_startup_linux(reporter):
    dirs = _linux_autostart_dirs()
    user_dir = dirs[0] if dirs else ""
    seen = set()
    n = 0
    for d in dirs:
        try:
            entries = sorted(e for e in os.listdir(d) if e.endswith(".desktop"))
        except OSError:
            continue
        for filename in entries:
            if filename in seen:
                continue
            seen.add(filename)
            path = os.path.join(d, filename)
            meta = _desktop_entry_summary(path)
            if meta["hidden"]:
                continue
            user_entry = os.path.abspath(d) == os.path.abspath(user_dir)
            blob = f"{meta['name']} {meta['exec']} {filename}"
            if not user_entry and not _OPTIONAL_STARTUP_RE.search(blob):
                continue
            if _ESSENTIAL_STARTUP_RE.search(blob):
                continue
            cmd = _linux_disable_desktop_cmd(
                path, filename, meta["name"], user_entry=user_entry)
            reporter.finding(
                "REVIEW", f"Autostart app: {meta['name']}",
                f"{meta['name']} starts from {path} at login. "
                f"{_startup_hint(meta['name'], meta['exec'])} "
                f"Command: {_truncate(meta['exec']) or '(not declared)'}",
                "Disable this autostart entry if it is a helper/updater you do not need.",
                fix_cmds=[cmd],
                source=path, command=meta["exec"],
            )
            n += 1

    if n == 0:
        reporter.ok("No optional desktop autostart entries found")
    return n


def check_startup(reporter):
    """Audit programs configured to launch at boot/login."""
    reporter.begin("STARTUP PROGRAMS",
                   "programs that auto-launch and quietly consume RAM/CPU")
    if _OS == "Windows":
        n = _check_startup_windows(reporter)
    elif _OS == "Darwin":
        n = _check_startup_macos(reporter)
    else:
        n = _check_startup_linux(reporter)
    reporter.end(f"{n} startup item(s) to review." if n else None)


# ── Gamer performance and protection checks ────────────────────────────────────

_WIN_HIGH_PERF_GUID = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
_WIN_ULTIMATE_PERF_GUID = "e9a42b02-d5df-448d-aa00-03f14749eb61"
_WIN_USB_SUBGROUP = "2a737441-1930-4402-8d77-b2bebba308a3"
_WIN_USB_SELECTIVE = "4f971e89-eebd-4455-a8de-9e59040e7347"
_WIN_PCIE_SUBGROUP = "501a4d13-42af-4429-9fd1-a8218c268e20"
_WIN_PCIE_ASPM = "ee12f906-d277-404b-b6da-e5fa1a576df5"


def _to_int(value):
    try:
        return int(str(value).strip(), 0)
    except (TypeError, ValueError):
        return None


def _win_power_ac_index(subgroup: str, setting: str):
    out, rc = _ps(f"powercfg /query SCHEME_CURRENT {subgroup} {setting}")
    if rc != 0:
        return None
    m = re.search(r"Current AC Power Setting Index:\s*0x([0-9a-fA-F]+)", out)
    if not m:
        return None
    return int(m.group(1), 16)


def _check_power_windows(reporter) -> int:
    n = 0
    out, rc = _ps("powercfg /getactivescheme")
    if rc == 0 and out.strip():
        low = out.lower()
        if _WIN_HIGH_PERF_GUID not in low and _WIN_ULTIMATE_PERF_GUID not in low:
            reporter.finding(
                "REVIEW", "Windows is not on a high-performance power plan",
                f"Active plan: {_truncate(out)}. Balanced/power-saver plans can add "
                "CPU parking and latency spikes while gaming on AC power.",
                "Switch to the built-in High performance plan before competitive gaming.",
                fix_cmds=["powercfg /setactive SCHEME_MIN"],
            )
            n += 1

    usb = _win_power_ac_index(_WIN_USB_SUBGROUP, _WIN_USB_SELECTIVE)
    if usb is not None and usb != 0:
        reporter.finding(
            "REVIEW", "USB selective suspend is enabled on AC power",
            "USB selective suspend can briefly power down idle USB devices. "
            "That is good for laptops, but can cause input/audio wake hiccups.",
            "Disable USB selective suspend for the active AC power plan.",
            fix_cmds=[
                f"powercfg /setacvalueindex SCHEME_CURRENT {_WIN_USB_SUBGROUP} "
                f"{_WIN_USB_SELECTIVE} 0; powercfg /setactive SCHEME_CURRENT"
            ],
        )
        n += 1

    pcie = _win_power_ac_index(_WIN_PCIE_SUBGROUP, _WIN_PCIE_ASPM)
    if pcie is not None and pcie != 0:
        reporter.finding(
            "REVIEW", "PCIe Link State Power Management is enabled on AC power",
            "PCIe ASPM saves power by downshifting links. On some gaming systems "
            "it can add latency when the GPU or NVMe device wakes back up.",
            "Turn PCIe Link State Power Management off for the active AC power plan.",
            fix_cmds=[
                f"powercfg /setacvalueindex SCHEME_CURRENT {_WIN_PCIE_SUBGROUP} "
                f"{_WIN_PCIE_ASPM} 0; powercfg /setactive SCHEME_CURRENT"
            ],
        )
        n += 1

    # CPU Core Parking — Balanced plan parks idle cores; all cores should be active for gaming
    _WIN_PROC_SUBGROUP  = "54533251-82be-4824-96c1-47b60b740d00"
    _WIN_CORE_PARK_MIN  = "0cc5b647-c1df-4637-891a-dec35c318583"
    park = _win_power_ac_index(_WIN_PROC_SUBGROUP, _WIN_CORE_PARK_MIN)
    if park is not None and park < 100:
        reporter.finding(
            "REVIEW", f"CPU Core Parking minimum is {park}% (cores can be parked)",
            "Windows parks idle CPU cores to save power. Parked cores take time to "
            "wake up, adding frame-time spikes when the game suddenly needs more threads.",
            "Set core parking minimum to 100% so all cores stay unparked.",
            fix_cmds=[
                f"powercfg /setacvalueindex SCHEME_CURRENT {_WIN_PROC_SUBGROUP} "
                f"{_WIN_CORE_PARK_MIN} 100; powercfg /setactive SCHEME_CURRENT"
            ],
        )
        n += 1

    # Timer resolution — default 15.6 ms tick; competitive games need 0.5 ms
    out, rc = _ps(
        "[System.Diagnostics.Stopwatch]::Frequency; "
        "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel' "
        "-Name GlobalTimerResolutionRequests -ErrorAction SilentlyContinue).GlobalTimerResolutionRequests",
        timeout=15,
    )
    # Check whether any app is already requesting high-res timer
    bcde_out, _ = _ps(
        "bcdedit /enum {current} 2>$null | Select-String 'useplatformtick'",
        timeout=15,
    )
    if "useplatformtick" not in bcde_out.lower():
        reporter.finding(
            "REVIEW", "Windows timer resolution may be at the default 15.6 ms",
            "The Windows multimedia timer defaults to a 15.6 ms tick. Competitive games "
            "work best at 0.5 ms resolution — some titles request this themselves, but "
            "enabling it system-wide ensures consistent scheduling.",
            "Force high-resolution timer via bcdedit (requires reboot) or install a "
            "per-session tool such as TimerResolution or ISLC.",
            fix_cmds=[
                "bcdedit /set {current} useplatformtick yes; "
                "bcdedit /set {current} disabledynamictick yes"
            ],
        )
        n += 1

    # Win32PrioritySeparation — 0x26 gives maximum foreground boost (2 quanta, variable)
    pri = _ps_int(
        "Get-ItemProperty "
        "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl' "
        "-Name Win32PrioritySeparation -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty Win32PrioritySeparation"
    )
    if pri is not None and pri not in (0x26, 0x28, 38, 40):
        reporter.finding(
            "REVIEW", f"Win32PrioritySeparation is 0x{pri:02x} (not tuned for gaming)",
            "This registry value controls how much CPU quantum the foreground window "
            "receives vs background processes. 0x26 gives the game maximum foreground "
            "priority with variable quanta — the most common competitive tweak.",
            "Set Win32PrioritySeparation to 0x26.",
            fix_cmds=[
                "Set-ItemProperty "
                "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl' "
                "-Name Win32PrioritySeparation -Value 0x26 -Type DWord -Force"
            ],
        )
        n += 1

    # Fast Startup — Windows writes a hibernation snapshot on shutdown, causing
    # incomplete hardware re-initialisation on next boot (GPU driver state can persist)
    hib = _ps_int(
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power' "
        "-Name HiberbootEnabled -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty HiberbootEnabled"
    )
    if hib == 1:
        reporter.finding(
            "INFO", "Windows Fast Startup is enabled",
            "Fast Startup saves a partial hibernation snapshot instead of fully powering "
            "off. This can leave GPU driver state and overclock profiles in a stale "
            "condition after a reboot, causing crashes or suboptimal clock speeds.",
            "Disable Fast Startup for a clean driver init on every boot.",
            fix_cmds=[
                "Set-ItemProperty "
                "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power' "
                "-Name HiberbootEnabled -Value 0 -Type DWord -Force"
            ],
        )
        n += 1

    return n


def _check_power_macos(reporter) -> int:
    n = 0
    try:
        r = subprocess.run(["pmset", "-g"], capture_output=True, text=True,
                           errors="replace", timeout=10)
        out = r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 0
    m = re.search(r"\blowpowermode\s+(\d+)", out)
    if m and m.group(1) == "1":
        reporter.finding(
            "REVIEW", "Low Power Mode is enabled",
            "Low Power Mode intentionally reduces energy use, which can throttle "
            "CPU/GPU performance during games.",
            "Turn Low Power Mode off before gaming.",
            fix_cmds=["pmset -a lowpowermode 0"],
        )
        n += 1
    return n


def _check_power_linux(reporter) -> int:
    n = 0
    if shutil.which("powerprofilesctl"):
        try:
            active = subprocess.run(["powerprofilesctl", "get"],
                                    capture_output=True, text=True,
                                    errors="replace", timeout=10).stdout.strip()
            listing = subprocess.run(["powerprofilesctl", "list"],
                                     capture_output=True, text=True,
                                     errors="replace", timeout=10).stdout
            if active and active != "performance" and "performance" in listing:
                reporter.finding(
                    "REVIEW", f"Linux power profile is '{active}'",
                    "The system power profile can cap boost behavior. "
                    "Performance mode is available on this machine.",
                    "Switch to the performance power profile before gaming.",
                    fix_cmds=["powerprofilesctl set performance"],
                )
                n += 1
        except (OSError, subprocess.TimeoutExpired):
            pass

    try:
        import glob as _glob
        govs = set()
        can_perf = False
        for path in _glob.glob("/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    govs.add(fh.read().strip())
                avail = path.replace("scaling_governor", "scaling_available_governors")
                with open(avail, "r", encoding="utf-8") as fh:
                    if "performance" in fh.read().split():
                        can_perf = True
            except OSError:
                pass
        if can_perf and govs and govs != {"performance"}:
            reporter.finding(
                "REVIEW", "CPU governor is not pinned to performance",
                f"Current governor(s): {', '.join(sorted(govs))}. "
                "Dynamic governors are usually fine, but performance mode can reduce "
                "frame-time variance on some Linux gaming rigs.",
                "Set CPU governors to performance for this session.",
                fix_cmds=[
                    "for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; "
                    "do [ -w \"$f\" ] && echo performance > \"$f\"; done"
                ],
            )
            n += 1
    except Exception:
        pass
    return n


def check_power_settings(reporter):
    """Audit local power settings that affect throttling and latency."""
    reporter.begin("POWER OPTIMIZATION",
                   "local power settings that can affect FPS, latency, and frame pacing")
    if _OS == "Windows":
        n = _check_power_windows(reporter)
    elif _OS == "Darwin":
        n = _check_power_macos(reporter)
    else:
        n = _check_power_linux(reporter)
    if n == 0:
        reporter.ok("Power settings look gaming-ready")
    reporter.end(f"{n} power tweak(s) to review." if n else None)


def _ps_int(cmd: str):
    out, rc = _ps(cmd)
    if rc != 0 or not out.strip():
        return None
    return _to_int(out.strip().splitlines()[-1])


def _check_gpu_windows(reporter) -> int:
    n = 0
    out, rc = _ps(
        "Get-CimInstance Win32_VideoController | "
        "Select-Object Name,DriverVersion,AdapterRAM | ConvertTo-Json",
        timeout=30,
    )
    if rc == 0 and out.strip():
        for gpu in _json_array(out):
            name = str(gpu.get("Name") or "")
            if "microsoft basic display" in name.lower():
                reporter.finding(
                    "HIGH", "Microsoft Basic Display Adapter is active",
                    "Windows is using the fallback display driver, so GPU acceleration "
                    "and game performance will be severely limited.",
                    "Install the correct GPU driver from Windows Update or the GPU vendor.",
                )
                n += 1

    hags = _ps_int(
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers' "
        "-Name HwSchMode -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty HwSchMode"
    )
    if hags == 1:
        reporter.finding(
            "REVIEW", "Hardware-accelerated GPU scheduling is disabled",
            "HAGS lets the GPU manage its own scheduling on supported hardware. "
            "Many modern gaming PCs benefit, though a reboot is required.",
            "Enable HAGS and reboot if your GPU/driver supports it.",
            fix_cmds=[
                "New-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers' "
                "-Name HwSchMode -Value 2 -PropertyType DWord -Force | Out-Null"
            ],
        )
        n += 1

    gm_vals = [
        _ps_int("Get-ItemProperty 'HKCU:\\Software\\Microsoft\\GameBar' "
                "-Name AllowAutoGameMode -ErrorAction SilentlyContinue | "
                "Select-Object -ExpandProperty AllowAutoGameMode"),
        _ps_int("Get-ItemProperty 'HKCU:\\Software\\Microsoft\\GameBar' "
                "-Name AutoGameModeEnabled -ErrorAction SilentlyContinue | "
                "Select-Object -ExpandProperty AutoGameModeEnabled"),
    ]
    if any(v == 0 for v in gm_vals):
        reporter.finding(
            "REVIEW", "Windows Game Mode is disabled",
            "Game Mode prioritizes game processes and reduces background update/driver "
            "interruptions while a game is running.",
            "Enable Game Mode for the current user.",
            fix_cmds=[
                "New-Item -Path 'HKCU:\\Software\\Microsoft\\GameBar' -Force | Out-Null; "
                "New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\GameBar' "
                "-Name AllowAutoGameMode -Value 1 -PropertyType DWord -Force | Out-Null; "
                "New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\GameBar' "
                "-Name AutoGameModeEnabled -Value 1 -PropertyType DWord -Force | Out-Null"
            ],
        )
        n += 1

    dvr_enabled = _ps_int(
        "Get-ItemProperty 'HKCU:\\System\\GameConfigStore' "
        "-Name GameDVR_Enabled -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty GameDVR_Enabled"
    )
    capture_enabled = _ps_int(
        "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR' "
        "-Name AppCaptureEnabled -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty AppCaptureEnabled"
    )
    if dvr_enabled == 1 or capture_enabled == 1:
        reporter.finding(
            "REVIEW", "Background game capture is enabled",
            "Game DVR/background capture can consume GPU encoder, disk, and CPU resources. "
            "Disable it if you do not use instant replay or capture.",
            "Turn off Windows background game capture.",
            fix_cmds=[
                "New-Item -Path 'HKCU:\\System\\GameConfigStore' -Force | Out-Null; "
                "New-ItemProperty -Path 'HKCU:\\System\\GameConfigStore' "
                "-Name GameDVR_Enabled -Value 0 -PropertyType DWord -Force | Out-Null; "
                "New-Item -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR' -Force | Out-Null; "
                "New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR' "
                "-Name AppCaptureEnabled -Value 0 -PropertyType DWord -Force | Out-Null"
            ],
        )
        n += 1

    # NVIDIA Low Latency Mode (Ultra) — via NV registry key
    nv_ll = _ps_int(
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class"
        "\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000' "
        "-Name RMProfCudaCtxFlags -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty RMProfCudaCtxFlags"
    )
    if nv_ll is None:
        # Try 0001 slot
        nv_ll = _ps_int(
            "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class"
            "\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0001' "
            "-Name RMProfCudaCtxFlags -ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty RMProfCudaCtxFlags"
        )
    # Only flag if NVIDIA GPU is present (driver class registry key existed)
    nv_present_out, _ = _ps(
        "Get-WmiObject Win32_VideoController -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Name -match 'NVIDIA' } | Measure-Object | "
        "Select-Object -ExpandProperty Count"
    )
    if _to_int(nv_present_out.strip()):
        reporter.finding(
            "INFO", "Verify NVIDIA Low Latency Mode is set to Ultra",
            "NVIDIA Low Latency Mode (Ultra) submits frames just-in-time to the GPU "
            "render queue, reducing input lag by 20–30% in many titles.",
            "Open NVIDIA Control Panel → Manage 3D Settings → Low Latency Mode → Ultra.",
        )
        n += 1

    # Variable Refresh Rate (VRR / G-Sync / FreeSync) — global Windows enable
    vrr = _ps_int(
        "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\DirectX\\UserGpuPreferences' "
        "-Name AllowTearing -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty AllowTearing"
    )
    vrr_win = _ps_int(
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers' "
        "-Name VRROptimizeEnable -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty VRROptimizeEnable"
    )
    if vrr is not None and vrr == 0:
        reporter.finding(
            "REVIEW", "Variable Refresh Rate (G-Sync / FreeSync) is not enabled system-wide",
            "VRR synchronises the monitor refresh to the game's frame rate, eliminating "
            "screen tearing and reducing stutter. It requires a compatible monitor and GPU.",
            "Enable VRR in Windows Settings → System → Display → Graphics settings → "
            "Variable refresh rate (or in the NVIDIA / AMD control panel).",
            fix_cmds=[
                "Set-ItemProperty 'HKCU:\\Software\\Microsoft\\DirectX\\UserGpuPreferences' "
                "-Name AllowTearing -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue"
            ],
        )
        n += 1

    # Full-screen optimizations — per-process disable can help some legacy DX9/11 games
    fso = _ps_int(
        "Get-ItemProperty 'HKCU:\\System\\GameConfigStore' "
        "-Name GameDVR_FSEBehaviorMode -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty GameDVR_FSEBehaviorMode"
    )
    if fso is not None and fso == 2:
        reporter.finding(
            "INFO", "Full-screen optimizations are globally disabled",
            "Full-screen optimizations can improve performance in modern DX12/Vulkan "
            "titles by letting Windows flip-discard frames. Globally disabling them "
            "helps some older games but hurts newer ones.",
            "Consider enabling full-screen optimizations globally and disabling "
            "only for specific problematic games via their executable properties.",
            fix_cmds=[
                "Set-ItemProperty 'HKCU:\\System\\GameConfigStore' "
                "-Name GameDVR_FSEBehaviorMode -Value 0 -Type DWord -Force"
            ],
        )
        n += 1

    # Multiplane Overlay (MPO) — causes stutter + flickering on many GPU/monitor combos
    mpo = _ps_int(
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\Dwm' "
        "-Name OverlayTestMode -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty OverlayTestMode"
    )
    if mpo is None or mpo != 5:
        reporter.finding(
            "REVIEW", "Multiplane Overlay (MPO) is not disabled",
            "MPO allows the GPU to composite multiple display planes independently. "
            "On many gaming systems it causes frame stutter, micro-freezes, or "
            "flickering artifacts, especially with G-Sync/FreeSync enabled. "
            "Disabling it is a well-known competitive fix (requires reboot).",
            "Disable MPO via registry (reboot required to take effect).",
            fix_cmds=[
                "New-Item -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\Dwm' "
                "-Force | Out-Null; "
                "Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\Dwm' "
                "-Name OverlayTestMode -Value 5 -Type DWord -Force"
            ],
        )
        n += 1

    # Enhance Pointer Precision (mouse acceleration) — should be OFF for gaming
    pp = _ps_int(
        "Get-ItemProperty 'HKCU:\\Control Panel\\Mouse' "
        "-Name MouseSpeed -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty MouseSpeed"
    )
    if pp is not None and pp != 0:
        reporter.finding(
            "HIGH", "Enhance Pointer Precision (mouse acceleration) is on",
            "Mouse acceleration changes how far the cursor moves based on movement "
            "speed, making aim inconsistent in FPS and RTS games. "
            "Every competitive player turns this off.",
            "Disable Enhance Pointer Precision.",
            fix_cmds=[
                "Set-ItemProperty 'HKCU:\\Control Panel\\Mouse' "
                "-Name MouseSpeed -Value 0 -Force; "
                "Set-ItemProperty 'HKCU:\\Control Panel\\Mouse' "
                "-Name MouseThreshold1 -Value 0 -Force; "
                "Set-ItemProperty 'HKCU:\\Control Panel\\Mouse' "
                "-Name MouseThreshold2 -Value 0 -Force"
            ],
        )
        n += 1

    # Resizable BAR (ReBAR) / Smart Access Memory
    rebar = _ps_int(
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class"
        "\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000' "
        "-Name KMD_EnableReBAR -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty KMD_EnableReBAR"
    )
    if rebar == 0:
        reporter.finding(
            "REVIEW", "Resizable BAR (ReBAR / Smart Access Memory) appears disabled",
            "Resizable BAR lets the CPU access the full GPU VRAM at once instead of "
            "in 256 MB windows. On supported GPU+motherboard combos it provides "
            "5–15% average FPS uplift in many titles.",
            "Enable Resizable BAR in UEFI/BIOS (usually under PCI/PCIe settings) "
            "and ensure Above 4G Decoding is also enabled.",
        )
        n += 1

    # Display refresh rate — verify monitor is actually running at its maximum rate
    out, rc = _ps(
        "Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue "
        "| Select-Object CurrentRefreshRate,MaxRefreshRate "
        "| ConvertTo-Json",
        timeout=15,
    )
    if rc == 0 and out.strip():
        for ctrl in _json_array(out):
            cur = ctrl.get("CurrentRefreshRate") or 0
            mx = ctrl.get("MaxRefreshRate") or 0
            try:
                cur, mx = int(cur), int(mx)
            except (TypeError, ValueError):
                continue
            if mx > 0 and cur < mx:
                reporter.finding(
                    "REVIEW", f"Monitor refresh rate is {cur} Hz but max is {mx} Hz",
                    "Your display supports a higher refresh rate but Windows is not using it. "
                    "Lower refresh rates add motion blur and increase display latency.",
                    f"Set refresh rate to {mx} Hz: Display Settings → Advanced display → "
                    "Choose a refresh rate.",
                )
                n += 1
            elif cur > 0 and cur <= 60:
                reporter.finding(
                    "INFO", f"Monitor refresh rate is {cur} Hz",
                    "60 Hz or below limits how smoothly motion is rendered. Gaming monitors "
                    "at 144 Hz+ provide a significant competitive advantage.",
                    "Consider a higher-refresh-rate monitor for competitive play.",
                )
                n += 1

    return n


def _check_gpu_macos(reporter) -> int:
    n = 0
    try:
        r = subprocess.run(["pmset", "-g"], capture_output=True, text=True,
                           errors="replace", timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return 0
    m = re.search(r"\bgpuswitch\s+(\d+)", r.stdout)
    if m and m.group(1) in ("0", "2"):
        mode = "integrated-only" if m.group(1) == "0" else "automatic graphics switching"
        reporter.finding(
            "REVIEW", f"GPU mode is {mode}",
            "Dual-GPU Intel Macs can trade graphics performance for battery life. "
            "Discrete-only mode can improve game consistency while plugged in.",
            "Switch to discrete GPU mode before gaming.",
            fix_cmds=["pmset -a gpuswitch 1"],
        )
        n += 1
    return n


def _check_gpu_linux(reporter) -> int:
    n = 0
    if shutil.which("nvidia-smi"):
        try:
            r = subprocess.run(
                ["nvidia-smi",
                 "--query-gpu=name,driver_version,persistence_mode",
                 "--format=csv,noheader,nounits"],
                capture_output=True, text=True, errors="replace", timeout=15,
            )
            for line in r.stdout.splitlines():
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 3 and parts[2].lower() == "disabled":
                    reporter.finding(
                        "REVIEW", f"NVIDIA persistence mode is disabled ({parts[0]})",
                        "Persistence mode keeps the NVIDIA driver initialized, reducing "
                        "startup latency for GPU workloads and some launchers.",
                        "Enable NVIDIA persistence mode for this boot.",
                        fix_cmds=["nvidia-smi -pm 1"],
                    )
                    n += 1
        except (OSError, subprocess.TimeoutExpired):
            pass

    try:
        import glob as _glob
        for path in _glob.glob("/sys/class/drm/card*/device/power_dpm_force_performance_level"):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    val = fh.read().strip()
            except OSError:
                continue
            if val == "low":
                reporter.finding(
                    "REVIEW", "AMD GPU is pinned to low power",
                    f"{path} is set to 'low', which can cap GPU clocks.",
                    "Switch the AMD GPU performance level back to auto.",
                    fix_cmds=[f"echo auto > {_shell_quote(path)}"],
                )
                n += 1
    except Exception:
        pass

    # AMDGPU power profile — 'auto' is fine; 'battery' or 'low' caps clocks
    import glob as _glob2
    for pp_path in _glob2.glob("/sys/class/drm/card*/device/power_dpm_state"):
        try:
            with open(pp_path, "r", encoding="utf-8") as fh:
                state = fh.read().strip()
            if state in ("battery", "low"):
                card = pp_path.split("/")[4]
                reporter.finding(
                    "REVIEW", f"AMD GPU ({card}) DPM state is '{state}'",
                    f"DPM state '{state}' limits GPU clock speeds below the "
                    "performance state, which can reduce frame rates.",
                    f"Switch {card} to 'performance' DPM state.",
                    fix_cmds=[f"echo performance > {_shell_quote(pp_path)}"],
                )
                n += 1
                break
        except OSError:
            pass

    # Vulkan ICD available — without it games fall back to OpenGL (lower perf)
    vulkan_dirs = [
        "/usr/share/vulkan/icd.d",
        "/etc/vulkan/icd.d",
        os.path.expanduser("~/.local/share/vulkan/icd.d"),
    ]
    vulkan_ok = any(
        os.path.isdir(d) and any(
            f.endswith(".json") for f in os.listdir(d)
        )
        for d in vulkan_dirs
        if os.path.isdir(d)
    )
    if not vulkan_ok and shutil.which("vulkaninfo"):
        try:
            r = subprocess.run(["vulkaninfo", "--summary"],
                               capture_output=True, text=True,
                               errors="replace", timeout=15)
            if r.returncode != 0 or "ERROR" in r.stdout:
                reporter.finding(
                    "REVIEW", "Vulkan ICD may not be properly installed",
                    "Vulkan is the preferred API for modern Linux games and Proton. "
                    "Without a working Vulkan ICD the game falls back to slower OpenGL.",
                    "Install the Vulkan ICD for your GPU: "
                    "mesa-vulkan-drivers (AMD/Intel) or nvidia-driver (NVIDIA).",
                )
                n += 1
        except (OSError, subprocess.TimeoutExpired):
            pass

    # NVIDIA overclock / persistence mode check already handled above
    return n


def check_gpu_settings(reporter):
    """Audit GPU-related local settings."""
    reporter.begin("GPU OPTIMIZATION",
                   "local GPU, capture, and driver settings for gaming")
    if _OS == "Windows":
        n = _check_gpu_windows(reporter)
    elif _OS == "Darwin":
        n = _check_gpu_macos(reporter)
    else:
        n = _check_gpu_linux(reporter)
    if n == 0:
        reporter.ok("GPU settings look gaming-ready")
    reporter.end(f"{n} GPU tweak(s) to review." if n else None)


def _mp_value_disabled(value) -> bool:
    if isinstance(value, bool):
        return not value
    val = str(value).strip().lower()
    return val in ("0", "disabled", "false", "off")


def _check_protection_windows(reporter) -> int:
    n = 0
    out, rc = _ps(
        "Get-MpPreference | Select-Object EnableControlledFolderAccess,"
        "PUAProtection,EnableNetworkProtection,DisableScriptScanning,"
        "DisableArchiveScanning,ExclusionPath,ExclusionProcess | ConvertTo-Json",
        timeout=30,
    )
    prefs = _json_array(out)[0] if rc == 0 and out.strip() and _json_array(out) else {}
    if prefs:
        if _mp_value_disabled(prefs.get("EnableControlledFolderAccess", 0)):
            reporter.finding(
                "MEDIUM", "Controlled Folder Access is off",
                "Controlled Folder Access can block ransomware-style writes to protected folders.",
                "Enable Controlled Folder Access. If a trusted game/mod tool is blocked, allow it explicitly.",
                fix_cmds=["Set-MpPreference -EnableControlledFolderAccess Enabled"],
            )
            n += 1
        if _mp_value_disabled(prefs.get("PUAProtection", 0)):
            reporter.finding(
                "MEDIUM", "Potentially unwanted app protection is off",
                "PUA protection blocks common bundleware, miners, and browser hijackers.",
                "Enable Microsoft Defender PUA protection.",
                fix_cmds=["Set-MpPreference -PUAProtection Enabled"],
            )
            n += 1
        if _mp_value_disabled(prefs.get("EnableNetworkProtection", 0)):
            reporter.finding(
                "REVIEW", "Defender network protection is off",
                "Network protection can block known malicious domains and outbound callbacks.",
                "Enable Defender network protection if it is supported on this edition.",
                fix_cmds=["Set-MpPreference -EnableNetworkProtection Enabled"],
            )
            n += 1
        if prefs.get("DisableScriptScanning") is True:
            reporter.finding(
                "HIGH", "Defender script scanning is disabled",
                "Script scanning catches PowerShell, JavaScript, and VBScript malware before execution.",
                "Re-enable script scanning.",
                fix_cmds=["Set-MpPreference -DisableScriptScanning $false"],
            )
            n += 1
        exclusions = []
        for key in ("ExclusionPath", "ExclusionProcess"):
            val = prefs.get(key)
            if isinstance(val, list):
                exclusions.extend(str(x) for x in val if x)
            elif val:
                exclusions.append(str(val))
        if exclusions:
            reporter.finding(
                "REVIEW", f"{len(exclusions)} Defender exclusion(s) configured",
                "Defender exclusions are powerful: malware in excluded paths/processes is not scanned. "
                "Keep only exclusions you created intentionally.",
                "Review Windows Security -> Virus & threat protection -> Exclusions.",
            )
            n += 1

    out, rc = _ps(
        "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol "
        "-ErrorAction SilentlyContinue | Select-Object -ExpandProperty State"
    )
    if rc == 0 and "enabled" in out.lower():
        reporter.finding(
            "HIGH", "SMBv1 protocol is enabled",
            "SMBv1 is obsolete and historically wormable. It should be disabled on gaming PCs.",
            "Disable SMBv1. Reboot may be required.",
            fix_cmds=["Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"],
        )
        n += 1

    rdp = _ps_int(
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' "
        "-Name fDenyTSConnections -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty fDenyTSConnections"
    )
    if rdp == 0:
        reporter.finding(
            "HIGH", "Remote Desktop is enabled",
            "RDP is a common brute-force and ransomware entry point if exposed.",
            "Disable Remote Desktop unless you deliberately use it behind a VPN.",
            fix_cmds=[
                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' "
                "-Name fDenyTSConnections -Value 1; "
                "Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue"
            ],
        )
        n += 1

    ra = _ps_int(
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance' "
        "-Name fAllowToGetHelp -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty fAllowToGetHelp"
    )
    if ra == 1:
        reporter.finding(
            "MEDIUM", "Remote Assistance is enabled",
            "Remote Assistance opens another path for interactive remote control.",
            "Turn Remote Assistance off unless you actively use it.",
            fix_cmds=[
                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance' "
                "-Name fAllowToGetHelp -Value 0"
            ],
        )
        n += 1

    # TPM 2.0 — required for Windows 11, BitLocker hardware binding, and many anti-cheat tools
    out, rc = _ps(
        "Get-WmiObject -Namespace root/cimv2/security/microsofttpm -Class Win32_Tpm "
        "-ErrorAction SilentlyContinue | "
        "Select-Object IsActivated_InitialValue,SpecVersion | ConvertTo-Json",
        timeout=20,
    )
    if rc == 0 and out.strip():
        for tpm in _json_array(out):
            spec = str(tpm.get("SpecVersion") or "")
            activated = tpm.get("IsActivated_InitialValue")
            if "2.0" not in spec:
                reporter.finding(
                    "REVIEW", f"TPM version is {spec or 'unknown'} (not 2.0)",
                    "TPM 2.0 is required for Windows 11, BitLocker, Windows Hello, and some "
                    "anti-cheat features. An older TPM may limit hardware-backed security.",
                    "Update UEFI firmware or enable TPM 2.0 in BIOS settings.",
                )
                n += 1
            elif activated is False:
                reporter.finding(
                    "MEDIUM", "TPM 2.0 is present but not activated",
                    "A disabled TPM means BitLocker, Windows Hello, and hardware-root "
                    "cryptography features are unavailable.",
                    "Activate the TPM in UEFI/BIOS settings.",
                )
                n += 1

    # Secure Boot
    out, rc = _ps("Confirm-SecureBootUEFI -ErrorAction SilentlyContinue", timeout=15)
    if rc == 0 and out.strip().lower() == "false":
        reporter.finding(
            "HIGH", "Secure Boot is disabled",
            "Secure Boot prevents unsigned bootloaders from loading before Windows. "
            "Many anti-cheat engines (Valorant, Easy Anti-Cheat) also verify Secure Boot.",
            "Enable Secure Boot in UEFI/BIOS settings.",
        )
        n += 1

    # Memory Integrity / HVCI (Core Isolation)
    hvci = _ps_int(
        "Get-ItemProperty "
        "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios"
        "\\HypervisorEnforcedCodeIntegrity' "
        "-Name Enabled -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty Enabled"
    )
    if hvci is not None and hvci == 0:
        reporter.finding(
            "MEDIUM", "Memory Integrity (HVCI) is disabled",
            "Memory Integrity uses the hypervisor to verify all kernel-mode drivers. "
            "It blocks kernel-level exploits and kernel-mode cheat/rootkit loaders.",
            "Enable Core Isolation → Memory Integrity in Windows Security → Device Security.",
            fix_cmds=[
                "Set-ItemProperty -Path "
                "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios"
                "\\HypervisorEnforcedCodeIntegrity' "
                "-Name Enabled -Value 1 -Type DWord -Force"
            ],
        )
        n += 1

    # UAC level (0 = never notify = effectively disabled)
    uac = _ps_int(
        "Get-ItemProperty "
        "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
        "-Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty ConsentPromptBehaviorAdmin"
    )
    if uac is not None and uac == 0:
        reporter.finding(
            "HIGH", "UAC is set to never notify (disabled)",
            "With UAC off, any process can silently elevate to admin. "
            "Malware in mods, cheats, or phishing downloads exploits this directly.",
            "Restore UAC to at least the default (Notify when apps make changes).",
            fix_cmds=[
                "Set-ItemProperty "
                "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
                "-Name ConsentPromptBehaviorAdmin -Value 5 -Type DWord -Force; "
                "Set-ItemProperty "
                "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
                "-Name EnableLUA -Value 1 -Type DWord -Force"
            ],
        )
        n += 1

    # AutoRun / AutoPlay for removable media (NoDriveTypeAutoRun = 0xFF disables all)
    ar = _ps_int(
        "Get-ItemProperty "
        "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' "
        "-Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty NoDriveTypeAutoRun"
    )
    if ar is None or ar != 0xFF:
        reporter.finding(
            "MEDIUM", "AutoRun is not fully disabled",
            "AutoRun silently launches programs from inserted USB drives and discs — "
            "one of the most common physical-access malware vectors. "
            "0xFF disables AutoRun for every drive type.",
            "Disable AutoRun for all drive types.",
            fix_cmds=[
                "Set-ItemProperty "
                "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' "
                "-Name NoDriveTypeAutoRun -Value 0xFF -Type DWord -Force; "
                "Set-ItemProperty "
                "'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' "
                "-Name NoDriveTypeAutoRun -Value 0xFF -Type DWord -Force"
            ],
        )
        n += 1

    # Windows Defender Real-Time Protection
    rt = _ps_int(
        "Get-MpComputerStatus -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty RealTimeProtectionEnabled"
    )
    if rt is not None and rt == 0:
        reporter.finding(
            "CRITICAL", "Windows Defender Real-Time Protection is off",
            "Real-time protection is the primary defence against malware dropped by "
            "infected mods, cheat injectors, or drive-by download exploits in game browsers.",
            "Re-enable Real-Time Protection in Windows Security.",
            fix_cmds=["Set-MpPreference -DisableRealtimeMonitoring $false"],
        )
        n += 1

    # Guest account enabled
    out, rc = _ps(
        "Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty Enabled"
    )
    if rc == 0 and out.strip().lower() == "true":
        reporter.finding(
            "MEDIUM", "Built-in Guest account is enabled",
            "The Guest account provides unauthenticated local access. "
            "It should be disabled on gaming and personal PCs.",
            "Disable the Guest account.",
            fix_cmds=["Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue"],
        )
        n += 1

    # BitLocker on system drive
    out, rc = _ps(
        "(Get-BitLockerVolume -MountPoint $env:SystemDrive "
        "-ErrorAction SilentlyContinue).VolumeStatus",
        timeout=20,
    )
    if rc == 0 and out.strip() and "fullydecrypted" in out.strip().lower():
        reporter.finding(
            "REVIEW", "BitLocker is not enabled on the system drive",
            "Without BitLocker, anyone who removes the drive (or boots a live USB) "
            "can read all game saves, credentials, and personal files without a password.",
            "Enable BitLocker via Windows Security → Device encryption, or the BitLocker control panel.",
        )
        n += 1

    # Exploit Protection — Force ASLR and DEP via ProcessMitigations
    ep_aslr = _ps_int(
        "Get-ProcessMitigation -System -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty ASLR | "
        "Select-Object -ExpandProperty ForceRelocateImages"
    )
    if ep_aslr is not None and str(ep_aslr).lower() == "off":
        reporter.finding(
            "MEDIUM", "Exploit Protection: Force ASLR is off",
            "Force ASLR compels DLLs that did not opt-in to ASLR to still be randomised. "
            "This closes a loophole exploits use against legacy-compiled modules.",
            "Enable Force ASLR in Windows Security → App & browser control → Exploit protection.",
            fix_cmds=[
                "Set-ProcessMitigation -System -Enable ForceRelocateImages"
            ],
        )
        n += 1

    return n


def _check_protection_macos(reporter) -> int:
    n = 0
    try:
        r = subprocess.run(["fdesetup", "status"], capture_output=True,
                           text=True, errors="replace", timeout=10)
        if "filevault is off" in r.stdout.lower():
            reporter.finding(
                "HIGH", "FileVault is off",
                "FileVault protects your data if the Mac is lost or stolen. "
                "It requires choosing and safely storing a recovery method.",
                "Enable FileVault in System Settings -> Privacy & Security -> FileVault.",
            )
            n += 1
    except (OSError, subprocess.TimeoutExpired):
        pass

    sff = shutil.which("socketfilterfw") or "/usr/libexec/ApplicationFirewall/socketfilterfw"
    try:
        r = subprocess.run([sff, "--getstealthmode"], capture_output=True,
                           text=True, errors="replace", timeout=10)
        if "disabled" in (r.stdout + r.stderr).lower():
            reporter.finding(
                "MEDIUM", "Firewall stealth mode is off",
                "Stealth mode stops the Mac from responding to some unsolicited probes.",
                "Enable firewall stealth mode.",
                fix_cmds=[f"{_shell_quote(sff)} --setstealthmode on"],
            )
            n += 1
    except (OSError, subprocess.TimeoutExpired):
        pass

    disabled_updates = []
    for key in ("CriticalUpdateInstall", "ConfigDataInstall"):
        try:
            r = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", key],
                capture_output=True, text=True, errors="replace", timeout=10,
            )
            if r.returncode == 0 and r.stdout.strip() == "0":
                disabled_updates.append(key)
        except (OSError, subprocess.TimeoutExpired):
            pass
    if disabled_updates:
        reporter.finding(
            "MEDIUM", "Background security updates are disabled",
            "macOS uses background security-configuration and system-data updates "
            "for protections such as XProtect and Gatekeeper data.",
            "Enable critical background security and config-data updates.",
            fix_cmds=[
                "defaults write /Library/Preferences/com.apple.SoftwareUpdate "
                "CriticalUpdateInstall -bool true; "
                "defaults write /Library/Preferences/com.apple.SoftwareUpdate "
                "ConfigDataInstall -bool true"
            ],
        )
        n += 1

    for cmd, label, sev, fix_cmd in [
        (["systemsetup", "-getremotelogin"], "Remote Login (SSH) is enabled",
         "REVIEW", "systemsetup -setremotelogin off"),
        (["systemsetup", "-getremoteappleevents"], "Remote Apple Events are enabled",
         "MEDIUM", "systemsetup -setremoteappleevents off"),
    ]:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               errors="replace", timeout=10)
            if "on" in r.stdout.lower():
                reporter.finding(
                    sev, label,
                    "Remote access services increase the attack surface when they are not needed.",
                    "Disable this sharing service unless you intentionally use it.",
                    fix_cmds=[fix_cmd],
                )
                n += 1
        except (OSError, subprocess.TimeoutExpired):
            pass

    # Gatekeeper — verifies app signatures and notarization before launch
    try:
        r = subprocess.run(["spctl", "--status"],
                           capture_output=True, text=True, errors="replace", timeout=10)
        if "disabled" in (r.stdout + r.stderr).lower():
            reporter.finding(
                "HIGH", "Gatekeeper is disabled",
                "Gatekeeper validates app signatures before launch. Disabling it allows "
                "any unsigned code to run silently — a common vector for macOS malware.",
                "Re-enable Gatekeeper.",
                fix_cmds=["spctl --master-enable"],
            )
            n += 1
    except (OSError, subprocess.TimeoutExpired):
        pass

    # SIP (System Integrity Protection)
    try:
        r = subprocess.run(["csrutil", "status"],
                           capture_output=True, text=True, errors="replace", timeout=10)
        combined = (r.stdout + r.stderr).lower()
        if "disabled" in combined or "unknown" in combined:
            reporter.finding(
                "HIGH", "System Integrity Protection (SIP) is disabled",
                "SIP prevents even root from modifying critical system files. "
                "Disabling it removes a major layer of macOS tamper-resistance "
                "and makes the system far more vulnerable to persistent malware.",
                "Re-enable SIP: boot into Recovery (⌘+R), open Terminal, run: csrutil enable",
            )
            n += 1
    except (OSError, subprocess.TimeoutExpired):
        pass

    # Guest user account
    try:
        r = subprocess.run(
            ["defaults", "read",
             "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"],
            capture_output=True, text=True, errors="replace", timeout=10,
        )
        if r.returncode == 0 and r.stdout.strip() == "1":
            reporter.finding(
                "MEDIUM", "Guest user account is enabled",
                "The Guest account allows login without a password. Files are wiped "
                "on logout, but the session still exposes all network services and browsing.",
                "Disable Guest user in System Settings → Users & Groups.",
                fix_cmds=[
                    "defaults write /Library/Preferences/com.apple.loginwindow "
                    "GuestEnabled -bool false"
                ],
            )
            n += 1
    except (OSError, subprocess.TimeoutExpired):
        pass

    # Screen lock idle timeout (0 = never locks)
    try:
        r = subprocess.run(
            ["defaults", "read", "com.apple.screensaver", "idleTime"],
            capture_output=True, text=True, errors="replace", timeout=10,
        )
        if r.returncode == 0:
            idle = int(r.stdout.strip() or "0")
            if idle == 0:
                reporter.finding(
                    "MEDIUM", "Screen lock is never triggered",
                    "Without an idle timeout the Mac is fully accessible when left "
                    "unattended. A 5–10 minute timeout balances security and convenience.",
                    "Set a lock timeout in System Settings → Lock Screen → "
                    "'Require password after screensaver begins or display is turned off'.",
                )
                n += 1
    except (OSError, subprocess.TimeoutExpired, ValueError):
        pass

    # Firewall enabled (application layer)
    sff = shutil.which("socketfilterfw") or \
          "/usr/libexec/ApplicationFirewall/socketfilterfw"
    try:
        r = subprocess.run([sff, "--getglobalstate"],
                           capture_output=True, text=True, errors="replace", timeout=10)
        if "disabled" in (r.stdout + r.stderr).lower():
            reporter.finding(
                "HIGH", "macOS Application Firewall is off",
                "The built-in firewall blocks unsolicited inbound connections to "
                "all apps. Disabling it exposes game servers, remote tools, and "
                "system services to the local network.",
                "Enable the firewall in System Settings → Network → Firewall.",
                fix_cmds=[f"{_shell_quote(sff)} --setglobalstate on"],
            )
            n += 1
    except (OSError, subprocess.TimeoutExpired):
        pass

    return n


def _check_protection_linux(reporter) -> int:
    n = 0
    if shutil.which("aa-status"):
        try:
            r = subprocess.run(["aa-status"], capture_output=True, text=True,
                               errors="replace", timeout=15)
            text = r.stdout + r.stderr
            if "apparmor module is not loaded" in text.lower():
                reporter.finding(
                    "MEDIUM", "AppArmor is not loaded",
                    "AppArmor confines applications with per-program policies on supported distributions.",
                    "Enable AppArmor using your distribution's security documentation.",
                )
                n += 1
            m = re.search(r"(\d+)\s+profiles are in complain mode", text)
            if m and int(m.group(1)) > 0:
                reporter.finding(
                    "REVIEW", f"{m.group(1)} AppArmor profile(s) are in complain mode",
                    "Complain mode logs policy violations but does not enforce denials.",
                    "Review and move mature profiles to enforce mode.",
                )
                n += 1
        except (OSError, subprocess.TimeoutExpired):
            pass

    if shutil.which("getenforce"):
        try:
            r = subprocess.run(["getenforce"], capture_output=True, text=True,
                               errors="replace", timeout=10)
            mode = r.stdout.strip()
            if mode == "Permissive":
                reporter.finding(
                    "MEDIUM", "SELinux is permissive",
                    "Permissive mode logs policy violations but does not block them.",
                    "Switch SELinux to enforcing after confirming policy health.",
                    fix_cmds=["setenforce 1"],
                )
                n += 1
            elif mode == "Disabled":
                reporter.finding(
                    "MEDIUM", "SELinux is disabled",
                    "SELinux can confine services and reduce post-exploit damage on supported distributions.",
                    "Enable SELinux in your distribution config and reboot after planning for relabeling.",
                )
                n += 1
        except (OSError, subprocess.TimeoutExpired):
            pass

    if shutil.which("apt-get"):
        auto_file = "/etc/apt/apt.conf.d/20auto-upgrades"
        enabled = False
        try:
            with open(auto_file, "r", encoding="utf-8", errors="replace") as fh:
                data = fh.read()
                enabled = 'APT::Periodic::Unattended-Upgrade "1"' in data
        except OSError:
            pass
        if not enabled:
            reporter.finding(
                "REVIEW", "Unattended security upgrades are not enabled",
                "Security updates should be applied promptly, especially on machines "
                "with launchers, mods, voice chat, and browsers open while gaming.",
                "Enable unattended security upgrades if this machine is not managed elsewhere.",
                fix_cmds=[
                    "printf '%s\\n' "
                    "'APT::Periodic::Update-Package-Lists \"1\";' "
                    "'APT::Periodic::Unattended-Upgrade \"1\";' "
                    "> /etc/apt/apt.conf.d/20auto-upgrades"
                ],
            )
            n += 1
    elif shutil.which("systemctl"):
        try:
            r = subprocess.run(["systemctl", "is-enabled", "dnf-automatic.timer"],
                               capture_output=True, text=True, errors="replace",
                               timeout=10)
            if r.returncode != 0 and "not-found" not in (r.stdout + r.stderr):
                reporter.finding(
                    "REVIEW", "dnf-automatic timer is not enabled",
                    "Automatic security update checks reduce the window of exposure.",
                    "Enable dnf-automatic if it is installed and appropriate for this PC.",
                    fix_cmds=["systemctl enable --now dnf-automatic.timer"],
                )
                n += 1
        except (OSError, subprocess.TimeoutExpired):
            pass

    # TCP SYN cookies (protection against SYN-flood)
    try:
        with open("/proc/sys/net/ipv4/tcp_syncookies", "r", encoding="utf-8") as fh:
            if fh.read().strip() == "0":
                reporter.finding(
                    "HIGH", "TCP SYN cookies are disabled",
                    "SYN cookies protect the system against SYN-flood DoS attacks that "
                    "exhaust the connection table and can disconnect gaming sessions.",
                    "Enable SYN cookies immediately.",
                    fix_cmds=["sysctl -w net.ipv4.tcp_syncookies=1"],
                )
                n += 1
    except OSError:
        pass

    # ASLR (full = 2)
    try:
        with open("/proc/sys/kernel/randomize_va_space", "r", encoding="utf-8") as fh:
            aslr = fh.read().strip()
        if aslr != "2":
            reporter.finding(
                "HIGH", f"ASLR is not fully enabled (randomize_va_space={aslr})",
                "Full ASLR (value 2) randomises heap, stack, VDSO, and shared-library "
                "addresses on every launch, making memory-corruption exploits much harder.",
                "Enable full ASLR.",
                fix_cmds=["sysctl -w kernel.randomize_va_space=2"],
            )
            n += 1
    except OSError:
        pass

    # dmesg_restrict — prevents non-root from reading kernel addresses from logs
    try:
        with open("/proc/sys/kernel/dmesg_restrict", "r", encoding="utf-8") as fh:
            if fh.read().strip() == "0":
                reporter.finding(
                    "MEDIUM", "Kernel log (dmesg) is readable by all users",
                    "dmesg can expose kernel addresses and device information useful "
                    "for local privilege-escalation exploits.",
                    "Restrict dmesg to root.",
                    fix_cmds=["sysctl -w kernel.dmesg_restrict=1"],
                )
                n += 1
    except OSError:
        pass

    # suid_dumpable — prevent core dumps from setuid/setgid processes
    try:
        with open("/proc/sys/fs/suid_dumpable", "r", encoding="utf-8") as fh:
            val = fh.read().strip()
        if val != "0":
            reporter.finding(
                "MEDIUM", "Core dumps are permitted for setuid processes",
                f"fs.suid_dumpable={val} allows setuid binaries to produce core dumps "
                "that can contain plaintext passwords and private keys from privileged memory.",
                "Disable setuid core dumps.",
                fix_cmds=["sysctl -w fs.suid_dumpable=0"],
            )
            n += 1
    except OSError:
        pass

    # kptr_restrict — kernel pointer leaks
    try:
        with open("/proc/sys/kernel/kptr_restrict", "r", encoding="utf-8") as fh:
            kptr = fh.read().strip()
        if kptr == "0":
            reporter.finding(
                "MEDIUM", "Kernel pointer leaks are not restricted",
                "kernel.kptr_restrict=0 lets all processes read kernel symbol addresses "
                "from /proc/kallsyms, aiding local exploits.",
                "Restrict kernel pointer exposure.",
                fix_cmds=["sysctl -w kernel.kptr_restrict=1"],
            )
            n += 1
    except OSError:
        pass

    # fail2ban
    if shutil.which("fail2ban-client"):
        try:
            r = subprocess.run(["systemctl", "is-active", "fail2ban"],
                               capture_output=True, text=True, errors="replace",
                               timeout=10)
            if r.returncode != 0:
                reporter.finding(
                    "REVIEW", "fail2ban is installed but not running",
                    "fail2ban blocks IPs showing brute-force patterns against SSH "
                    "and other services. Running it protects exposed ports.",
                    "Start and enable fail2ban.",
                    fix_cmds=["systemctl enable --now fail2ban"],
                )
                n += 1
        except (OSError, subprocess.TimeoutExpired):
            pass

    # auditd
    if shutil.which("auditd") or shutil.which("auditctl"):
        try:
            r = subprocess.run(["systemctl", "is-active", "auditd"],
                               capture_output=True, text=True, errors="replace",
                               timeout=10)
            if r.returncode != 0:
                reporter.finding(
                    "INFO", "Linux Audit daemon (auditd) is not running",
                    "auditd provides fine-grained auditing of system calls, file access, "
                    "and privilege escalation events — essential for incident response.",
                    "Enable auditd.",
                    fix_cmds=["systemctl enable --now auditd"],
                )
                n += 1
        except (OSError, subprocess.TimeoutExpired):
            pass

    # SSH: root login should be disabled
    sshd_cfg = "/etc/ssh/sshd_config"
    try:
        with open(sshd_cfg, "r", encoding="utf-8", errors="replace") as fh:
            sshd_text = fh.read()
        if re.search(r"^\s*PermitRootLogin\s+yes", sshd_text, re.MULTILINE | re.IGNORECASE):
            reporter.finding(
                "HIGH", "SSH permits root login",
                "Allowing root login over SSH collapses the two-factor principle "
                "(break-in + privilege escalation into one step).",
                "Set PermitRootLogin no in /etc/ssh/sshd_config.",
                fix_cmds=["sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' "
                          f"{_shell_quote(sshd_cfg)} && systemctl reload sshd 2>/dev/null || true"],
            )
            n += 1
    except OSError:
        pass

    return n


def check_protection_hardening(reporter):
    """Audit high-value local protection controls beyond the base scan."""
    reporter.begin("PROTECTION HARDENING",
                   "extra local controls for ransomware, remote access, and exploit resistance")
    if _OS == "Windows":
        n = _check_protection_windows(reporter)
    elif _OS == "Darwin":
        n = _check_protection_macos(reporter)
    else:
        n = _check_protection_linux(reporter)
    if n == 0:
        reporter.ok("Advanced protection controls look healthy")
    reporter.end(f"{n} protection tweak(s) to review." if n else None)


# ── Network performance ────────────────────────────────────────────────────────

def _check_network_perf_windows(reporter) -> int:
    n = 0

    # Nagle's algorithm — batches TCP packets, adds 10-40 ms to online game latency
    out, rc = _ps(
        "Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip"
        "\\Parameters\\Interfaces' -ErrorAction SilentlyContinue | "
        "ForEach-Object { Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue } | "
        "Select-Object TcpAckFrequency,TCPNoDelay | ConvertTo-Json",
        timeout=20,
    )
    if rc == 0 and out.strip():
        nagle_ifaces = [
            iface for iface in _json_array(out)
            if iface.get("TcpAckFrequency") is not None
            or iface.get("TCPNoDelay") is not None
        ]
        nagle_on = any(
            iface.get("TcpAckFrequency") != 1 or iface.get("TCPNoDelay") != 1
            for iface in nagle_ifaces
        )
        if nagle_on or not nagle_ifaces:
            reporter.finding(
                "REVIEW", "Nagle's algorithm may be active on one or more NICs",
                "Nagle batches small TCP packets to reduce bandwidth usage. "
                "For competitive online gaming this can add 10–40 ms of "
                "input-to-server latency.",
                "Disable Nagle by setting TcpAckFrequency=1 and TCPNoDelay=1 "
                "on every NIC interface.",
                fix_cmds=[
                    "Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services"
                    "\\Tcpip\\Parameters\\Interfaces' -ErrorAction SilentlyContinue"
                    " | ForEach-Object {"
                    " Set-ItemProperty $_.PSPath -Name TcpAckFrequency -Value 1"
                    " -Type DWord -Force -ErrorAction SilentlyContinue;"
                    " Set-ItemProperty $_.PSPath -Name TCPNoDelay -Value 1"
                    " -Type DWord -Force -ErrorAction SilentlyContinue }"
                ],
            )
            n += 1

    # RSS (Receive Side Scaling) — spread NIC interrupts across cores
    out, rc = _ps(
        "(Get-NetAdapterAdvancedProperty -RegistryKeyword '*RSS*' "
        "-ErrorAction SilentlyContinue "
        "| Where-Object { $_.RegistryValue -eq '0' }).Count",
        timeout=15,
    )
    if rc == 0:
        cnt = _to_int(out.strip())
        if cnt and cnt > 0:
            reporter.finding(
                "REVIEW", f"{cnt} NIC(s) have Receive Side Scaling disabled",
                "RSS distributes packet processing across CPU cores, preventing a "
                "single-core bottleneck during heavy gaming and streaming traffic.",
                "Enable RSS on all physical adapters.",
                fix_cmds=["Enable-NetAdapterRss -Name * -ErrorAction SilentlyContinue"],
            )
            n += 1

    # NIC energy-efficient Ethernet — throttles NIC during low-activity bursts
    out, rc = _ps(
        "(Get-NetAdapterAdvancedProperty -RegistryKeyword '*EnergySaving*' "
        "-ErrorAction SilentlyContinue "
        "| Where-Object { $_.RegistryValue -ne '0' }).Count",
        timeout=15,
    )
    if rc == 0:
        cnt = _to_int(out.strip())
        if cnt and cnt > 0:
            reporter.finding(
                "REVIEW", "NIC Energy Efficient Ethernet (EEE) is enabled",
                "EEE throttles the NIC during idle periods. When a game suddenly "
                "sends a burst of traffic, the NIC wake-up adds measurable latency.",
                "Turn off energy saving on all physical adapters.",
                fix_cmds=[
                    "Get-NetAdapter -Physical | ForEach-Object {"
                    " Set-NetAdapterAdvancedProperty -Name $_.Name"
                    " -RegistryKeyword '*EnergySaving*' -RegistryValue '0'"
                    " -ErrorAction SilentlyContinue;"
                    " Set-NetAdapterAdvancedProperty -Name $_.Name"
                    " -RegistryKeyword 'EEE' -RegistryValue '0'"
                    " -ErrorAction SilentlyContinue }"
                ],
            )
            n += 1

    # Network throttling index (0xFFFFFFFF = disabled = no throttling)
    nti = _ps_int(
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
        "\\Multimedia\\SystemProfile' "
        "-Name NetworkThrottlingIndex -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty NetworkThrottlingIndex"
    )
    if nti is not None and nti != 0xFFFFFFFF:
        reporter.finding(
            "REVIEW", "Windows network throttling is active",
            "Windows throttles non-multimedia network flows to guarantee bandwidth "
            "for audio/video. Setting NetworkThrottlingIndex to 0xFFFFFFFF disables "
            "this cap, which can reduce gaming latency.",
            "Disable network throttling for gaming.",
            fix_cmds=[
                "Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT"
                "\\CurrentVersion\\Multimedia\\SystemProfile' "
                "-Name NetworkThrottlingIndex -Value 0xFFFFFFFF -Type DWord -Force"
            ],
        )
        n += 1

    return n


def _check_network_perf_linux(reporter) -> int:
    n = 0

    # TCP receive buffer ceiling
    try:
        with open("/proc/sys/net/core/rmem_max", "r", encoding="utf-8") as fh:
            rmem_max = int(fh.read().strip())
        if rmem_max < 16_777_216:
            reporter.finding(
                "REVIEW", f"TCP receive buffer cap is {rmem_max // (1024*1024)} MB",
                "A 16 MB+ TCP receive buffer lets the kernel absorb large incoming "
                "bursts from game servers without dropping packets.",
                "Increase TCP buffer ceilings for this session.",
                fix_cmds=[
                    "sysctl -w net.core.rmem_max=16777216; "
                    "sysctl -w net.core.wmem_max=16777216; "
                    "sysctl -w net.ipv4.tcp_rmem='4096 87380 16777216'; "
                    "sysctl -w net.ipv4.tcp_wmem='4096 65536 16777216'"
                ],
            )
            n += 1
    except (OSError, ValueError):
        pass

    # IRQ balance — all interrupts on CPU0 without it
    if shutil.which("irqbalance"):
        try:
            r = subprocess.run(["systemctl", "is-active", "irqbalance"],
                               capture_output=True, text=True, errors="replace",
                               timeout=10)
            if r.returncode != 0:
                reporter.finding(
                    "REVIEW", "irqbalance is not running",
                    "Without irqbalance, all hardware interrupts (NIC, disk) land on "
                    "CPU0, which can saturate that core during heavy network I/O.",
                    "Start irqbalance to distribute interrupts across cores.",
                    fix_cmds=["systemctl enable --now irqbalance"],
                )
                n += 1
        except (OSError, subprocess.TimeoutExpired):
            pass

    return n


def _check_network_perf_macos(reporter) -> int:
    n = 0
    # Most macOS TCP tuning is automatic; check basics
    try:
        r = subprocess.run(["sysctl", "net.inet.tcp.delayed_ack"],
                           capture_output=True, text=True, errors="replace", timeout=10)
        m = re.search(r"=\s*(\d+)", r.stdout)
        if m and int(m.group(1)) > 0:
            reporter.finding(
                "INFO", "TCP delayed ACK is active",
                "Delayed ACK batches acknowledgement packets — normally fine, but can "
                "add a round-trip delay for latency-sensitive online games.",
                "Consider setting net.inet.tcp.delayed_ack=0 for gaming sessions "
                "(sudo sysctl -w net.inet.tcp.delayed_ack=0).",
            )
            n += 1
    except (OSError, subprocess.TimeoutExpired):
        pass
    return n


def check_network_perf(reporter):
    """Audit NIC, TCP stack, and network settings that affect online gaming latency."""
    reporter.begin("NETWORK OPTIMIZATION",
                   "NIC power, TCP stack, and latency tweaks for competitive online gaming")
    if _OS == "Windows":
        n = _check_network_perf_windows(reporter)
    elif _OS == "Darwin":
        n = _check_network_perf_macos(reporter)
    else:
        n = _check_network_perf_linux(reporter)
    if n == 0:
        reporter.ok("Network settings look gaming-ready")
    reporter.end(f"{n} network tweak(s) to review." if n else None)


# ── Memory and system tuning ───────────────────────────────────────────────────

def _check_memory_windows(reporter) -> int:
    n = 0

    # SystemResponsiveness (0 = give game max CPU; 20 = default)
    resp = _ps_int(
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
        "\\Multimedia\\SystemProfile' "
        "-Name SystemResponsiveness -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty SystemResponsiveness"
    )
    if resp is not None and resp != 0:
        reporter.finding(
            "REVIEW", f"Multimedia SystemResponsiveness is {resp} (optimal is 0)",
            "Windows reserves this % of CPU for background multimedia tasks. "
            "Setting it to 0 lets the active game monopolise CPU slices.",
            "Set SystemResponsiveness to 0 for gaming sessions.",
            fix_cmds=[
                "Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT"
                "\\CurrentVersion\\Multimedia\\SystemProfile' "
                "-Name SystemResponsiveness -Value 0 -Type DWord -Force"
            ],
        )
        n += 1

    # Games multimedia profile — GPU Priority should be 8, Priority 6
    gp = _ps_int(
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
        "\\Multimedia\\SystemProfile\\Tasks\\Games' "
        "-Name 'GPU Priority' -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty 'GPU Priority'"
    )
    if gp is not None and gp < 8:
        reporter.finding(
            "REVIEW", f"Games multimedia profile GPU Priority is {gp} (optimal is 8)",
            "The Games multimedia profile hints the GPU scheduler to prioritise "
            "game workloads. GPU Priority 8 + Scheduling Category High reduces "
            "frame-time variance on many systems.",
            "Maximise the Games multimedia profile.",
            fix_cmds=[
                "New-Item -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT"
                "\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games' "
                "-Force | Out-Null; "
                "$p = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
                "\\Multimedia\\SystemProfile\\Tasks\\Games'; "
                "Set-ItemProperty $p -Name 'GPU Priority' -Value 8 -Type DWord -Force; "
                "Set-ItemProperty $p -Name 'Priority' -Value 6 -Type DWord -Force; "
                "Set-ItemProperty $p -Name 'Scheduling Category' -Value 'High' "
                "-Type String -Force; "
                "Set-ItemProperty $p -Name 'SFIO Priority' -Value 'High' "
                "-Type String -Force"
            ],
        )
        n += 1

    # Window animations (MinAnimate) — minor GPU overhead on low-end systems
    vi_key = "HKCU:\\Control Panel\\Desktop\\WindowMetrics"
    vi_val = _ps_int(
        f"Get-ItemProperty {_ps_quote(vi_key)} "
        "-Name MinAnimate -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty MinAnimate"
    )
    if vi_val is not None and vi_val != 0:
        reporter.finding(
            "INFO", "Window minimize/maximize animations are enabled",
            "UI animations consume small GPU slices on every window event. "
            "Disabling them is one of several 'best performance' tweaks.",
            "Disable animations: System → Advanced system settings → Performance → "
            "Adjust for best performance.",
            fix_cmds=[
                f"Set-ItemProperty {_ps_quote(vi_key)} "
                "-Name MinAnimate -Value 0 -Force"
            ],
        )
        n += 1

    # Page file — missing page file can crash some games/launchers
    out, rc = _ps(
        "(Get-WmiObject Win32_PageFileUsage -ErrorAction SilentlyContinue | "
        "Measure-Object).Count",
        timeout=15,
    )
    if rc == 0 and _to_int(out.strip()) == 0:
        reporter.finding(
            "REVIEW", "No active page file detected",
            "Some games and launchers require a page file even when the system has "
            "large amounts of RAM. Running without one can cause crashes.",
            "Enable the system-managed page file in Advanced System Settings → "
            "Performance → Virtual memory.",
        )
        n += 1

    # SysMain (Superfetch) — pre-loads apps into RAM; causes random disk I/O mid-game
    out, rc = _ps(
        "Get-Service -Name SysMain -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty Status"
    )
    if rc == 0 and out.strip().lower() == "running":
        reporter.finding(
            "REVIEW", "SysMain (Superfetch) is running",
            "SysMain pre-fetches files it predicts you'll need, causing background "
            "disk reads that compete with game streaming. Many competitive players "
            "disable it, especially on SSDs where the benefit is minimal.",
            "Disable SysMain if you experience random disk activity mid-game.",
            fix_cmds=[
                "Stop-Service SysMain -Force -ErrorAction SilentlyContinue; "
                "Set-Service SysMain -StartupType Disabled"
            ],
        )
        n += 1

    # Windows Search Indexing — background I/O spikes during play
    out, rc = _ps(
        "Get-Service -Name WSearch -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty Status"
    )
    if rc == 0 and out.strip().lower() == "running":
        reporter.finding(
            "INFO", "Windows Search Indexing service is running",
            "The indexer can trigger sustained disk reads/writes during or after "
            "large file operations (game updates, mod installs), causing frame drops.",
            "Consider disabling WSearch if you do not use Windows Search extensively.",
            fix_cmds=[
                "Stop-Service WSearch -Force -ErrorAction SilentlyContinue; "
                "Set-Service WSearch -StartupType Disabled"
            ],
        )
        n += 1

    # Windows Update Delivery Optimisation (P2P seeding eats upstream bandwidth)
    dop2p = _ps_int(
        "Get-ItemProperty "
        "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
        "\\DeliveryOptimization\\Config' "
        "-Name DODownloadMode -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty DODownloadMode"
    )
    if dop2p is not None and dop2p in (1, 3):
        label = "Internet + LAN" if dop2p == 3 else "LAN peers"
        reporter.finding(
            "REVIEW", f"Windows Update delivery optimisation is seeding to {label}",
            "Delivery Optimisation uploads Windows Update chunks to other PCs on "
            "your network or the internet. The upload can saturate your connection "
            "and spike ping mid-match.",
            "Restrict delivery optimisation to local network only, or disable it.",
            fix_cmds=[
                "Set-ItemProperty "
                "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
                "\\DeliveryOptimization\\Config' "
                "-Name DODownloadMode -Value 1 -Type DWord -Force"
            ],
        )
        n += 1

    # RAM XMP / EXPO — verify sticks are running at their rated speed
    out, rc = _ps(
        "Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue "
        "| Select-Object Speed,ConfiguredClockSpeed | ConvertTo-Json",
        timeout=15,
    )
    if rc == 0 and out.strip():
        xmp_mismatch = False
        for stick in _json_array(out):
            rated = stick.get("Speed") or 0
            actual = stick.get("ConfiguredClockSpeed") or 0
            try:
                rated, actual = int(rated), int(actual)
            except (TypeError, ValueError):
                continue
            if rated > 0 and actual > 0 and actual < rated * 0.95:
                xmp_mismatch = True
                break
        if xmp_mismatch:
            reporter.finding(
                "REVIEW", f"RAM is running below its rated speed ({actual} MHz vs {rated} MHz rated)",
                "Your memory sticks are rated faster than they are currently clocked. "
                "Without XMP (Intel) or EXPO (AMD) enabled in BIOS, RAM runs at the "
                "JEDEC default (typically 2133–3200 MHz). Enabling XMP/EXPO can improve "
                "frame rates by 5–20% in CPU-bound games.",
                "Enter UEFI/BIOS → AI Tweaker / D.O.C.P / EXPO profile → Enable XMP/EXPO.",
            )
            n += 1

    # Visual Effects — Windows Aero animations and transparency cost GPU compositor time
    vfx = _ps_int(
        "Get-ItemProperty "
        "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects' "
        "-Name VisualFXSetting -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty VisualFXSetting"
    )
    if vfx is not None and vfx != 2:
        reporter.finding(
            "INFO", "Windows visual effects are not set to 'Adjust for best performance'",
            "Transparency, animations, and live thumbnails run on the DWM compositor "
            "and consume GPU memory bandwidth. On lower-end systems this competes "
            "directly with the game's frame budget.",
            "Set visual effects to best performance: "
            "System → Advanced system settings → Performance → Adjust for best performance.",
            fix_cmds=[
                "Set-ItemProperty "
                "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects' "
                "-Name VisualFXSetting -Value 2 -Type DWord -Force; "
                "Stop-Process -Name explorer -Force; Start-Process explorer"
            ],
        )
        n += 1

    # Windows Defender — suggest adding game library exclusions to prevent shader stutter
    out, rc = _ps(
        "(Get-MpPreference -ErrorAction SilentlyContinue).ExclusionPath",
        timeout=15,
    )
    if rc == 0:
        existing = set(p.strip().lower() for p in out.splitlines() if p.strip())
        steam_paths = [
            r"c:\program files (x86)\steam\steamapps",
            r"c:\program files\steam\steamapps",
        ]
        if not any(p in existing for p in steam_paths):
            reporter.finding(
                "INFO", "Steam library has no Windows Defender exclusion",
                "When a game installs or compiles shaders, Defender scans every new DLL "
                "and compiled cache file in real-time. This causes multi-second stutters "
                "during shader compilation passes. Excluding the game library folder "
                "eliminates this entirely.",
                "Add your Steam library to Defender exclusions in Windows Security → "
                "Virus & threat protection → Manage settings → Exclusions.",
                fix_cmds=[
                    "Add-MpPreference -ExclusionPath "
                    "'C:\\Program Files (x86)\\Steam\\steamapps' -ErrorAction SilentlyContinue; "
                    "Add-MpPreference -ExclusionPath "
                    "'C:\\Program Files\\Steam\\steamapps' -ErrorAction SilentlyContinue"
                ],
            )
            n += 1

    return n


def _check_memory_linux(reporter) -> int:
    n = 0

    # Swappiness (default 60 aggressively evicts RAM pages to swap)
    try:
        with open("/proc/sys/vm/swappiness", "r", encoding="utf-8") as fh:
            swappiness = int(fh.read().strip())
        if swappiness > 20:
            reporter.finding(
                "REVIEW", f"vm.swappiness is {swappiness} (high for gaming)",
                "A high swappiness causes the kernel to move game data to swap "
                "before RAM is full, causing multi-second micro-stutters when pages "
                "are demanded back.",
                "Lower swappiness to 10 for this session.",
                fix_cmds=["sysctl -w vm.swappiness=10"],
            )
            n += 1
    except (OSError, ValueError):
        pass

    # Transparent Huge Pages — 'always' causes compaction pauses
    try:
        with open("/sys/kernel/mm/transparent_hugepage/enabled", "r",
                  encoding="utf-8") as fh:
            thp = fh.read().strip()
        if "[always]" in thp:
            reporter.finding(
                "REVIEW", "Transparent Huge Pages is set to 'always'",
                "THP=always triggers background memory compaction that can stall "
                "page allocation for 10–100 ms — visible as mid-game frame hitches.",
                "Switch to madvise mode so only opt-in apps get huge pages.",
                fix_cmds=[
                    "echo madvise > /sys/kernel/mm/transparent_hugepage/enabled"
                ],
            )
            n += 1
    except OSError:
        pass

    # vm.dirty_ratio — high value causes periodic synchronous I/O flushes
    try:
        with open("/proc/sys/vm/dirty_ratio", "r", encoding="utf-8") as fh:
            dirty = int(fh.read().strip())
        if dirty > 10:
            reporter.finding(
                "REVIEW", f"vm.dirty_ratio is {dirty}% (can cause I/O stall spikes)",
                f"When {dirty}% of RAM holds dirty (unwritten) pages the kernel "
                "forces a synchronous flush. During a shader compile or auto-save "
                "this can freeze the frame for hundreds of milliseconds.",
                "Lower dirty_ratio for smoother disk I/O.",
                fix_cmds=["sysctl -w vm.dirty_ratio=5; "
                          "sysctl -w vm.dirty_background_ratio=3"],
            )
            n += 1
    except (OSError, ValueError):
        pass

    # Feral GameMode — all-in-one gaming performance daemon
    if not shutil.which("gamemoded") and not shutil.which("gamemode"):
        reporter.finding(
            "INFO", "Feral GameMode is not installed",
            "GameMode applies CPU governor, GPU performance level, I/O scheduler, "
            "and process niceness tweaks automatically when a game launches. "
            "Many Steam and Proton titles activate it via the launch command "
            "(%command% → gamemoderun %command%).",
            "Install via your package manager: sudo apt install gamemode  "
            "or: sudo dnf install gamemode",
        )
        n += 1

    # I/O scheduler — CFQ/BFQ add fairness overhead on SSDs/NVMe
    import glob as _glob
    for sched_path in sorted(
        _glob.glob("/sys/block/*/queue/scheduler")
    )[:3]:
        dev = sched_path.split("/")[3]
        if dev.startswith(("loop", "ram", "sr", "fd")):
            continue
        try:
            with open(sched_path, "r", encoding="utf-8") as fh:
                sched = fh.read().strip()
            active = re.search(r"\[(\w+)\]", sched)
            if active and active.group(1) in ("cfq", "bfq"):
                reporter.finding(
                    "REVIEW", f"I/O scheduler on {dev} is {active.group(1).upper()}",
                    f"CFQ/BFQ add fairness queuing suited for HDDs. "
                    "For NVMe/SSDs, 'none' or 'mq-deadline' cuts I/O latency "
                    "and reduces shader-cache jitter.",
                    f"Switch {dev} to mq-deadline.",
                    fix_cmds=[
                        f"echo mq-deadline > /sys/block/{dev}/queue/scheduler"
                    ],
                )
                n += 1
                break
        except OSError:
            pass

    # esync / fsync — Wine/Proton needs high file-descriptor limits
    try:
        import resource as _resource
        soft, hard = _resource.getrlimit(_resource.RLIMIT_NOFILE)
        if hard < 524288:
            reporter.finding(
                "REVIEW", f"File-descriptor hard limit is {hard} (low for esync)",
                "Wine/Proton's esync uses one file descriptor per Windows sync object. "
                "Games with thousands of objects need a hard limit of at least 524288. "
                "Without it, Proton silently falls back to slower wineserver sync.",
                "Add 'hard nofile 524288' and 'soft nofile 524288' to /etc/security/limits.conf "
                "(or /etc/security/limits.d/esync.conf) and re-login.",
            )
            n += 1
    except Exception:
        pass

    # CPU frequency pinning — set min_freq = max_freq to eliminate boost ramp latency
    import glob as _glob2
    min_paths = sorted(_glob2.glob(
        "/sys/devices/system/cpu/cpu*/cpufreq/scaling_min_freq"))[:4]
    max_paths = sorted(_glob2.glob(
        "/sys/devices/system/cpu/cpu*/cpufreq/scaling_max_freq"))[:4]
    if min_paths and max_paths:
        try:
            with open(min_paths[0], "r", encoding="utf-8") as fh:
                cur_min = int(fh.read().strip())
            with open(max_paths[0], "r", encoding="utf-8") as fh:
                cur_max = int(fh.read().strip())
            if cur_min < cur_max:
                reporter.finding(
                    "INFO", "CPU minimum frequency is below maximum (boost ramp active)",
                    f"CPU0 runs between {cur_min//1000} MHz and {cur_max//1000} MHz. "
                    "When a game thread wakes, the CPU may briefly run at the lower "
                    "clock before boosting. Pinning min=max eliminates this ramp-up "
                    "latency (increases power consumption).",
                    "Pin all CPU cores to their maximum frequency for this session.",
                    fix_cmds=[
                        "for cpu in /sys/devices/system/cpu/cpu*/cpufreq; do "
                        "  max=$(cat $cpu/cpuinfo_max_freq 2>/dev/null) || continue; "
                        "  [ -w $cpu/scaling_min_freq ] && echo $max > $cpu/scaling_min_freq; "
                        "done"
                    ],
                )
                n += 1
        except (OSError, ValueError):
            pass

    # MangoHud — performance overlay for Linux gaming
    if not shutil.which("mangohud"):
        reporter.finding(
            "INFO", "MangoHud is not installed",
            "MangoHud is the standard performance overlay for Linux gaming — "
            "shows FPS, frame time, CPU/GPU usage, temperatures, and VRAM usage "
            "inside any Vulkan or OpenGL game with zero overhead.",
            "Install MangoHud: sudo apt install mangohud  or  sudo dnf install mangohud",
        )
        n += 1

    # DXVK/VKD3D hugepages — pre-allocated huge pages speed up shader cache access
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            meminfo = fh.read()
        m = re.search(r"HugePages_Free:\s+(\d+)", meminfo)
        total_m = re.search(r"HugePages_Total:\s+(\d+)", meminfo)
        if m and total_m and int(total_m.group(1)) == 0:
            reporter.finding(
                "INFO", "No huge pages are pre-allocated",
                "DXVK and VKD3D-Proton perform internal shader compiler allocations "
                "that benefit from 2 MB huge pages. Pre-allocating a pool can reduce "
                "shader compilation stutter on first play.",
                "Allocate huge pages for this session: "
                "sudo sysctl -w vm.nr_hugepages=512",
            )
            n += 1
    except OSError:
        pass

    # Spectre/Meltdown mitigations — trade security for CPU performance (INFO only)
    try:
        with open("/sys/devices/system/cpu/vulnerabilities/spectre_v2", "r",
                  encoding="utf-8") as fh:
            spec = fh.read().strip()
        if "mitigation" in spec.lower():
            reporter.finding(
                "INFO", "CPU Spectre/Meltdown mitigations are active",
                "Kernel mitigations for Spectre, Meltdown, and related vulnerabilities "
                "reduce CPU throughput by 2–15% in some workloads. Some gamers add "
                "'mitigations=off' to the kernel boot line for a performance gain — "
                "this is a deliberate security trade-off, not a safe default fix.",
                "Only disable mitigations if you understand the security implications. "
                "Edit /etc/default/grub and add mitigations=off to GRUB_CMDLINE_LINUX.",
            )
            n += 1
    except OSError:
        pass

    return n


def _check_memory_macos(reporter) -> int:
    n = 0

    # Reduce Transparency — frosted-glass layers cost GPU memory bandwidth
    try:
        r = subprocess.run(
            ["defaults", "read",
             "com.apple.universalaccess", "reduceTransparency"],
            capture_output=True, text=True, errors="replace", timeout=10,
        )
        if r.returncode == 0 and r.stdout.strip() == "0":
            reporter.finding(
                "INFO", "macOS transparency effects are active",
                "Frosted-glass transparency requires compositing many layers on "
                "every frame. On Macs where every GPU clock matters, enabling "
                "Reduce Transparency frees bandwidth for the game.",
                "Enable Reduce Transparency in System Settings → Accessibility → Display.",
            )
            n += 1
    except (OSError, subprocess.TimeoutExpired):
        pass

    # Spotlight indexing — can spike CPU/IO at unpredictable times
    try:
        r = subprocess.run(
            ["mdutil", "-s", "/"],
            capture_output=True, text=True, errors="replace", timeout=10,
        )
        if "indexing enabled" in (r.stdout + r.stderr).lower():
            reporter.finding(
                "INFO", "Spotlight indexing is active on the system volume",
                "Spotlight re-indexes modified files. During a game install or "
                "patch it can cause sustained CPU/IO spikes lasting several minutes.",
                "Add your game library folder to Spotlight Privacy exclusions: "
                "System Settings → Siri & Spotlight → Spotlight Privacy.",
            )
            n += 1
    except (OSError, subprocess.TimeoutExpired):
        pass

    # App Nap — can throttle apps in the background (rarely affects games but good to know)
    try:
        r = subprocess.run(
            ["defaults", "read", "NSGlobalDomain", "NSAppSleepDisabled"],
            capture_output=True, text=True, errors="replace", timeout=10,
        )
        if r.returncode != 0 or r.stdout.strip() != "1":
            reporter.finding(
                "INFO", "App Nap is enabled globally",
                "App Nap throttles background apps to save power. On gaming Macs, "
                "this can affect launcher/overlay processes running alongside the game.",
                "Disable App Nap globally for smoother background app performance.",
                fix_cmds=[
                    "defaults write NSGlobalDomain NSAppSleepDisabled -bool YES; "
                    "killall Dock"
                ],
            )
            n += 1
    except (OSError, subprocess.TimeoutExpired):
        pass

    # Bluetooth — active 2.4 GHz scanning interferes with wireless peripherals
    try:
        r = subprocess.run(
            ["defaults", "read", "/Library/Preferences/com.apple.Bluetooth",
             "ControllerPowerState"],
            capture_output=True, text=True, errors="replace", timeout=10,
        )
        if r.returncode == 0 and r.stdout.strip() == "1":
            reporter.finding(
                "INFO", "Bluetooth is enabled",
                "If you use wired peripherals, active Bluetooth RF scanning occupies "
                "the 2.4 GHz band and can interfere with wireless mice/headsets "
                "from other devices in the same band.",
                "Disable Bluetooth when using wired peripherals: "
                "System Settings → Bluetooth → Turn Bluetooth Off.",
                fix_cmds=[
                    "defaults write /Library/Preferences/com.apple.Bluetooth "
                    "ControllerPowerState -int 0; "
                    "killall -HUP bluetoothd 2>/dev/null || true"
                ],
            )
            n += 1
    except (OSError, subprocess.TimeoutExpired):
        pass

    # Time Machine — continuous backups cause sustained I/O during gaming
    try:
        r = subprocess.run(
            ["tmutil", "status"],
            capture_output=True, text=True, errors="replace", timeout=10,
        )
        if "Running = 1" in r.stdout:
            reporter.finding(
                "REVIEW", "Time Machine backup is actively running",
                "A Time Machine backup in progress can saturate disk I/O and USB/Thunderbolt "
                "bandwidth, causing frame drops and shader cache stutters.",
                "Pause backups before gaming.",
                fix_cmds=["tmutil stopbackup"],
            )
            n += 1
        # Also check if TM is enabled with no exclusions for game library
        r2 = subprocess.run(
            ["tmutil", "destinationinfo"],
            capture_output=True, text=True, errors="replace", timeout=10,
        )
        if r2.returncode == 0 and r2.stdout.strip():
            reporter.finding(
                "INFO", "Time Machine is enabled — consider adding game library exclusions",
                "Time Machine backs up every file change. Adding your Steam/game library "
                "folder as an exclusion prevents game updates from triggering multi-GB "
                "backups mid-session.",
                "Add exclusions: tmutil addexclusion ~/Library/Application\\ Support/Steam",
            )
            n += 1
    except (OSError, subprocess.TimeoutExpired):
        pass

    # Notification Centre — can interrupt games with banners
    try:
        r = subprocess.run(
            ["defaults", "read", "com.apple.notificationcenterui", "doNotDisturb"],
            capture_output=True, text=True, errors="replace", timeout=10,
        )
        dnd_on = r.returncode == 0 and r.stdout.strip() == "1"
        if not dnd_on:
            reporter.finding(
                "INFO", "Do Not Disturb / Focus is not active",
                "Notification banners wake the GPU compositor and can briefly interrupt "
                "full-screen games. Enable Focus or Do Not Disturb while gaming.",
                "Enable Do Not Disturb: System Settings → Focus → Do Not Disturb.",
            )
            n += 1
    except (OSError, subprocess.TimeoutExpired):
        pass

    return n


def check_memory_perf(reporter):
    """Audit RAM, swap, I/O, and OS responsiveness settings for stutter-free gaming."""
    reporter.begin("SYSTEM TUNING",
                   "RAM pressure, swap, I/O scheduler, and OS responsiveness for smooth gaming")
    if _OS == "Windows":
        n = _check_memory_windows(reporter)
    elif _OS == "Darwin":
        n = _check_memory_macos(reporter)
    else:
        n = _check_memory_linux(reporter)
    if n == 0:
        reporter.ok("System tuning looks gaming-ready")
    reporter.end(f"{n} tuning item(s) to review." if n else None)


# ── System resources ───────────────────────────────────────────────────────────

def check_system_resources(reporter):
    """Check live system health: VPN, free RAM, disk capacity, and CPU hogs."""
    reporter.begin("LIVE SYSTEM HEALTH",
                   "VPN presence, available RAM, disk space, and background CPU hogs")
    n = 0

    # ── VPN detection ──────────────────────────────────────────────────────────
    try:
        if _OS == "Windows":
            out = _ps(
                "(Get-NetAdapter | Where-Object {"
                " $_.InterfaceDescription -match 'VPN|Tunnel|WireGuard|OpenVPN|Nord|Express|Proton'"
                " -or $_.Name -match 'VPN|Tunnel|WireGuard|tun|tap'"
                " } | Where-Object { $_.Status -eq 'Up' } | Measure-Object).Count"
            )
            vpn_up = out.strip() not in ("", "0")
        elif _OS == "Darwin":
            r = subprocess.run(
                ["networksetup", "-listallnetworkservices"],
                capture_output=True, text=True, errors="replace", timeout=10,
            )
            vpn_names = [ln for ln in r.stdout.splitlines()
                         if any(k in ln.lower() for k in ("vpn", "tunnel", "wireguard",
                                                            "openvpn", "nordvpn", "expressvpn"))]
            # Also check ifconfig for tun/tap
            r2 = subprocess.run(
                ["ifconfig"], capture_output=True, text=True, errors="replace", timeout=10,
            )
            vpn_up = bool(vpn_names) or bool(
                [ln for ln in r2.stdout.splitlines()
                 if ln.startswith(("tun", "utun", "tap")) and "RUNNING" in r2.stdout]
            )
        else:
            r = subprocess.run(
                ["ip", "link", "show"],
                capture_output=True, text=True, errors="replace", timeout=10,
            )
            vpn_up = any(
                kw in r.stdout.lower()
                for kw in ("tun0", "tun1", "tap0", "wg0", "nordlynx", "proton0")
            )
        if vpn_up:
            reporter.finding(
                "INFO", "VPN is active",
                "An active VPN adds encryption overhead and can increase game latency by "
                "10–100 ms. Unless your game requires it, disconnect before competitive play.",
                "Disconnect your VPN before gaming for the lowest possible ping.",
            )
            n += 1
    except (OSError, subprocess.TimeoutExpired):
        pass

    # ── Free RAM ───────────────────────────────────────────────────────────────
    try:
        if _OS == "Windows":
            free_mb = _ps_int(
                "(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory", default=None
            )
            if free_mb is not None:
                free_mb //= 1024  # KiB → MiB
        elif _OS == "Darwin":
            r = subprocess.run(
                ["vm_stat"], capture_output=True, text=True, errors="replace", timeout=10,
            )
            page_size = 16384  # macOS default 16 KB pages
            free_pages = 0
            for line in r.stdout.splitlines():
                if line.startswith("Pages free:") or line.startswith("Pages speculative:"):
                    try:
                        free_pages += int(line.split(":")[1].strip().rstrip("."))
                    except ValueError:
                        pass
            free_mb = (free_pages * page_size) // (1024 * 1024)
        else:
            with open("/proc/meminfo") as f:
                info = {ln.split(":")[0].strip(): ln.split(":")[1].strip()
                        for ln in f if ":" in ln}
            avail = info.get("MemAvailable", "0 kB").split()[0]
            free_mb = int(avail) // 1024

        if free_mb is not None and free_mb < 3072:
            reporter.finding(
                "REVIEW", f"Low available RAM: {free_mb} MB free",
                "Less than 3 GB of RAM available. Games that dynamically stream assets "
                "(open-world, UE5 titles) will stutter as the OS pages data to disk.",
                "Close background applications before launching the game. Consider "
                "upgrading RAM if this is consistently below 4 GB.",
            )
            n += 1
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass

    # ── Disk capacity ──────────────────────────────────────────────────────────
    try:
        if _OS == "Windows":
            # Report all fixed drives above 90 % full
            out = _ps(
                "Get-PSDrive -PSProvider FileSystem | Where-Object {"
                " $_.Used -and ($_.Used / ($_.Used + $_.Free)) -gt 0.90"
                " } | ForEach-Object {"
                " $pct = [int]($_.Used / ($_.Used + $_.Free) * 100);"
                " \"$($_.Root) $pct%\""
                " }"
            )
            drives = [ln.strip() for ln in out.splitlines() if ln.strip()]
        elif _OS == "Darwin":
            r = subprocess.run(
                ["df", "-H", "/"],
                capture_output=True, text=True, errors="replace", timeout=10,
            )
            drives = []
            for line in r.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    pct = int(parts[4].rstrip("%"))
                    if pct > 90:
                        drives.append(f"{parts[5]} {pct}%")
        else:
            r = subprocess.run(
                ["df", "-H", "--output=pcent,target"],
                capture_output=True, text=True, errors="replace", timeout=10,
            )
            drives = []
            for line in r.stdout.splitlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 2:
                    try:
                        pct = int(parts[0].rstrip("%"))
                        if pct > 90:
                            drives.append(f"{parts[1]} {pct}%")
                    except ValueError:
                        pass

        if drives:
            label = ", ".join(drives)
            reporter.finding(
                "REVIEW", f"Drive almost full: {label}",
                "Drives over 90 % capacity cause the OS to fragment writes, slowing "
                "shader caches and game installs. Some games refuse to save or crash "
                "when free space drops below 1 GB.",
                "Free up space by uninstalling unused games, clearing browser caches, "
                "and emptying the Recycle Bin / Trash.",
            )
            n += 1
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass

    # ── Background CPU hogs ────────────────────────────────────────────────────
    try:
        if _OS == "Windows":
            out = _ps(
                "Get-Process | Where-Object { $_.CPU -and $_.Name -notmatch "
                "'Idle|System|Registry|svchost|csrss|lsass|winlogon|smss|wininit|fontdrvhost' }"
                " | Sort-Object CPU -Descending | Select-Object -First 5"
                " | ForEach-Object { \"$($_.Name) [$([int]($_.CPU))s CPU]\" }"
            )
            hogs = [ln.strip() for ln in out.splitlines() if ln.strip()]
            # Filter to processes with meaningful CPU (heuristic: >8% would need
            # per-core sampling; we report top-5 by cumulative CPU seconds instead)
            if len(hogs) >= 3:
                reporter.finding(
                    "INFO", f"Background processes using CPU: {', '.join(hogs[:3])}",
                    "These processes have accumulated the most CPU time since boot. "
                    "If they are still actively running, they can steal CPU time from games.",
                    "Close or disable unnecessary background apps before gaming.",
                )
                n += 1
        else:
            # Use ps to find processes above 8 % CPU
            r = subprocess.run(
                ["ps", "axo", "pid,pcpu,comm", "--sort=-pcpu"],
                capture_output=True, text=True, errors="replace", timeout=10,
            )
            hogs = []
            skip_names = {"ps", "python3", "python", "exposure_check", "bash", "sh",
                          "launchd", "systemd", "kworker", "idle"}
            for line in r.stdout.splitlines()[1:11]:
                parts = line.strip().split(None, 2)
                if len(parts) < 3:
                    continue
                try:
                    pcpu = float(parts[1])
                except ValueError:
                    continue
                name = parts[2].split("/")[-1][:20]
                if pcpu >= 8.0 and not any(sk in name.lower() for sk in skip_names):
                    hogs.append(f"{name} ({pcpu:.0f}%)")
            if hogs:
                reporter.finding(
                    "REVIEW", f"CPU hog(s) detected: {', '.join(hogs[:4])}",
                    "These processes are using ≥8 % CPU right now, leaving fewer cycles "
                    "for your game. Stutters and frame-time spikes are likely while they run.",
                    "Identify and close these processes before gaming.",
                )
                n += 1
    except (OSError, subprocess.TimeoutExpired):
        pass

    # ── Thermal throttling ─────────────────────────────────────────────────────
    try:
        if _OS == "Windows":
            out, rc = _ps(
                "Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue "
                "| Select-Object Name,CurrentClockSpeed,MaxClockSpeed | ConvertTo-Json",
                timeout=15,
            )
            if rc == 0 and out.strip():
                for cpu in _json_array(out):
                    cur = cpu.get("CurrentClockSpeed") or 0
                    mx = cpu.get("MaxClockSpeed") or 0
                    name = cpu.get("Name", "CPU")
                    try:
                        cur, mx = int(cur), int(mx)
                    except (TypeError, ValueError):
                        continue
                    if mx > 0 and cur < mx * 0.85:
                        reporter.finding(
                            "REVIEW",
                            f"CPU may be thermally throttling: {cur} MHz vs {mx} MHz max",
                            f"{name} is running at {cur} MHz — {int(cur/mx*100)}% of its "
                            f"rated {mx} MHz. This usually means the CPU is too hot and has "
                            "reduced its own clock speed to stay within thermal limits. "
                            "Expect severe frame-rate drops and stutters.",
                            "Check CPU temperature (Core Temp / HWiNFO), clean dust from "
                            "heatsink/fans, re-apply thermal paste if over 2 years old, and "
                            "ensure the case has adequate airflow.",
                        )
                        n += 1
                        break
        elif _OS == "Linux":
            throttled = False
            cpu_paths = sorted(__import__("glob").glob(
                "/sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq"
            ))
            max_paths = sorted(__import__("glob").glob(
                "/sys/devices/system/cpu/cpu*/cpufreq/scaling_max_freq"
            ))
            for cp, mp in zip(cpu_paths[:4], max_paths[:4]):
                try:
                    cur = int(open(cp).read().strip())
                    mx = int(open(mp).read().strip())
                    if mx > 0 and cur < mx * 0.80:
                        throttled = True
                        break
                except (OSError, ValueError):
                    continue
            if throttled:
                reporter.finding(
                    "REVIEW", "CPU frequency is well below maximum — possible thermal throttle",
                    "One or more CPU cores are running significantly below their rated "
                    "maximum frequency. Thermal throttling is the most common cause: "
                    "the CPU reduces clocks to stay within safe temperatures.",
                    "Check CPU temperature with `sensors` or `s-tui`, clean dust, "
                    "and ensure adequate case airflow.",
                )
                n += 1
        elif _OS == "Darwin":
            r = subprocess.run(
                ["sysctl", "-n", "machdep.xcpm.cpu_thermal_level"],
                capture_output=True, text=True, errors="replace", timeout=10,
            )
            if r.returncode == 0:
                level = int(r.stdout.strip())
                if level > 0:
                    reporter.finding(
                        "REVIEW", f"CPU thermal pressure level is {level} (throttling active)",
                        "macOS is actively throttling CPU performance to manage heat. "
                        "This will reduce game frame rates and increase frame-time variance.",
                        "Check Activity Monitor → CPU History, clean vents, and ensure "
                        "the Mac is on a hard flat surface for proper airflow.",
                    )
                    n += 1
    except Exception:
        pass

    if n == 0:
        reporter.ok("Live system health looks good — no VPN, plenty of RAM and disk")
    reporter.end(f"{n} resource issue(s) found." if n else None)


# ── Port scan ──────────────────────────────────────────────────────────────────

def resolve_target(target):
    """Validate/resolve the target. Returns (ip, display) or exits cleanly."""
    try:
        ip = str(ipaddress.ip_address(target))
        return ip, target
    except ValueError:
        pass
    try:
        ip = socket.gethostbyname(target)
        return ip, f"{target} ({ip})"
    except socket.gaierror:
        sys.exit(f"[!] Could not resolve '{target}'. Use a valid IP or hostname.")


def check_port(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return port if s.connect_ex((ip, port)) == 0 else None
    except OSError:
        return None
    finally:
        s.close()


def scan(ip, ports, timeout, workers=100):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(check_port, ip, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            if (res := fut.result()) is not None:
                open_ports.append(res)
    return sorted(open_ports)


def describe(port):
    if port in RISKY_PORTS:
        return RISKY_PORTS[port]
    if port in SPECIAL:
        return SPECIAL[port]
    return (f"Port {port}", "INFO", "Open port (not in the risk database).",
            "Confirm this service is intended and protected.")


def _port_fix_cmds(port: int, severity: str) -> list:
    """Return firewall block commands for an exposed port.

    INFO and REVIEW ports are advisory-only — no automated fix is appropriate.
    For actionable severities we block the port at the OS firewall so the
    exposure is closed immediately, independent of whatever service owns it.
    """
    if severity in ("INFO", "REVIEW"):
        return []
    p = str(port)
    if _OS == "Windows":
        return [
            f'netsh advfirewall firewall add rule '
            f'name="Block port {p} (exposure-checker)" '
            f'dir=in action=block protocol=TCP localport={p}'
        ]
    if _OS == "Darwin":
        return [
            f'echo "block in proto tcp from any to any port {p}"'
            f' >> /etc/pf.conf',
            "pfctl -ef /etc/pf.conf",
        ]
    # Linux — ufw preferred; fall back to iptables
    if shutil.which("ufw"):
        return [f"ufw deny {p}/tcp"]
    return [f"iptables -A INPUT -p tcp --dport {p} -j DROP"]


def run_port_scan(reporter, ip, display, timeout):
    reporter._data.setdefault("target", display)
    reporter.begin("PORT SCAN", f"Target : {display}")
    all_ports = sorted(set(RISKY_PORTS) | set(SPECIAL))
    reporter.info(f"Checking {len(all_ports)} commonly-risky ports...")
    if not reporter.json_mode:
        print()

    open_ports = scan(ip, all_ports, timeout)

    if not open_ports:
        reporter.ok("No risky ports found open — small attack surface")
        return

    findings = sorted(
        ((p,) + describe(p) for p in open_ports),
        key=lambda f: SEVERITY_ORDER.get(f[2], 9),
    )
    if not reporter.json_mode:
        print(f"[!] {len(open_ports)} open port(s) found:")
    for port, service, severity, why, fix in findings:
        reporter.finding(severity, f"port {port} - {service}", why, fix,
                         port=port, service=service,
                         fix_cmds=_port_fix_cmds(port, severity))

    crit = sum(1 for f in findings if f[2] == "CRITICAL")
    high = sum(1 for f in findings if f[2] == "HIGH")
    reporter.end(f"{crit} critical, {high} high-risk open. Review above.")


# ── Diff ──────────────────────────────────────────────────────────────────────

def _save_baseline(path, data):
    """Persist report data as the baseline. Creates parent directories as needed."""
    parent = os.path.dirname(path)
    if parent:
        try:
            os.makedirs(parent, exist_ok=True)
        except OSError as e:
            return str(e)
    try:
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        return None
    except OSError as e:
        return str(e)


def _load_report(path):
    """Load and validate a saved JSON report. Returns (data, error_or_None)."""
    try:
        with open(path) as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return None, f"file not found: {path}"
    except json.JSONDecodeError as e:
        return None, f"invalid JSON in {path}: {e}"
    except OSError as e:
        return None, f"could not read {path}: {e}"
    if "checks" not in data or "timestamp" not in data:
        return None, f"{path} does not look like an exposure-checker report (missing 'checks' or 'timestamp')"
    return data, None


def diff_reports(before, after):
    """Compare two report dicts.  Returns:
        new      – (check, label, severity) found in after but not before
        resolved – (check, label, severity) found in before but not after
        changed  – (check, label, before_sev, after_sev) where severity shifted
    Findings are keyed by (check_name, label); duplicate keys keep the last entry.
    """
    def _index(data):
        idx = {}
        for check in data.get("checks", []):
            name = check.get("check", "")
            for f in check.get("findings", []):
                idx[(name, f.get("label", ""))] = f.get("severity", "UNKNOWN")
        return idx

    b, a = _index(before), _index(after)
    b_keys, a_keys = set(b), set(a)

    new      = sorted((k[0], k[1], a[k]) for k in a_keys - b_keys)
    resolved = sorted((k[0], k[1], b[k]) for k in b_keys - a_keys)
    changed  = sorted(
        (k[0], k[1], b[k], a[k])
        for k in b_keys & a_keys
        if b[k] != a[k]
    )
    return {"new": new, "resolved": resolved, "changed": changed}


def _print_diff(before_path, after_path, before_data, after_data, diff):
    b_ts = before_data.get("timestamp", "unknown")
    a_ts = after_data.get("timestamp", "unknown")

    print("=" * 66)
    print("  EXPOSURE CHECKER — DIFF")
    print(f"  Before : {b_ts}  ({before_path})")
    print(f"  After  : {a_ts}  ({after_path})")
    print("=" * 66)

    new, resolved, changed = diff["new"], diff["resolved"], diff["changed"]

    if not new and not resolved and not changed:
        print("\n[+] No changes between the two reports.\n")
        return

    if new:
        print(f"\nNEW ({len(new)}) ── findings that appeared:\n")
        for check, label, sev in sorted(new, key=lambda f: SEVERITY_ORDER.get(f[2], 9)):
            print(f"  [{sev}] {check} / {label}")

    if resolved:
        print(f"\nRESOLVED ({len(resolved)}) ── findings that disappeared:\n")
        for check, label, sev in sorted(resolved, key=lambda f: SEVERITY_ORDER.get(f[2], 9)):
            print(f"  [{sev}] {check} / {label}")

    if changed:
        print(f"\nCHANGED ({len(changed)}) ── severity shifted:\n")
        for check, label, b_sev, a_sev in sorted(
            changed, key=lambda f: SEVERITY_ORDER.get(f[3], 9)
        ):
            print(f"  [{b_sev} → {a_sev}] {check} / {label}")

    parts = []
    if new:      parts.append(f"{len(new)} new")
    if resolved: parts.append(f"{len(resolved)} resolved")
    if changed:  parts.append(f"{len(changed)} changed")
    print()
    print("-" * 66)
    print(f"  {' | '.join(parts)}")
    print("-" * 66)


def _diff_main(argv):
    parser = argparse.ArgumentParser(
        prog="exposure-checker diff",
        description="Compare two saved --output reports and show what changed.",
    )
    parser.add_argument("before", help="Baseline report (JSON file saved with --output).")
    parser.add_argument("after",  help="Current report (JSON file saved with --output).")
    parser.add_argument("--json", action="store_true",
                        help="Emit the diff as JSON.")
    parser.add_argument("--fail-on", metavar="SEVERITY",
                        choices=["critical", "high", "medium", "review", "info"],
                        type=str.lower,
                        help="Exit 1 if any NEW finding is at or above SEVERITY.")
    args = parser.parse_args(argv)

    before_data, err = _load_report(args.before)
    if err:
        sys.exit(f"[!] {err}")
    after_data, err = _load_report(args.after)
    if err:
        sys.exit(f"[!] {err}")

    diff = diff_reports(before_data, after_data)

    if args.json:
        print(json.dumps({
            "before":   {"file": args.before, "timestamp": before_data.get("timestamp")},
            "after":    {"file": args.after,  "timestamp": after_data.get("timestamp")},
            "new":      [{"check": c, "label": l, "severity": s} for c, l, s in diff["new"]],
            "resolved": [{"check": c, "label": l, "severity": s} for c, l, s in diff["resolved"]],
            "changed":  [{"check": c, "label": l, "before": b, "after": a}
                         for c, l, b, a in diff["changed"]],
        }, indent=2))
    else:
        _print_diff(args.before, args.after, before_data, after_data, diff)

    if args.fail_on:
        threshold = SEVERITY_ORDER.get(args.fail_on.upper(), 9)
        triggered = [(c, l, s) for c, l, s in diff["new"]
                     if SEVERITY_ORDER.get(s, 9) <= threshold]
        if triggered:
            if not args.json:
                print(
                    f"\n[!] --fail-on {args.fail_on}: "
                    f"{len(triggered)} new finding(s) at or above "
                    f"{args.fail_on.upper()}."
                )
            sys.exit(1)


# ── Risk score ────────────────────────────────────────────────────────────────

_SCORE_WEIGHTS = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 3, "REVIEW": 1, "INFO": 0}


def _compute_score(report_data):
    """Return (score 0–100, grade A–F). Each finding deducts weighted points."""
    deductions = 0
    for check in report_data.get("checks", []):
        for f in check.get("findings", []):
            deductions += _SCORE_WEIGHTS.get(f.get("severity", ""), 0)
    score = max(0, 100 - deductions)
    if score >= 90:   grade = "A"
    elif score >= 75: grade = "B"
    elif score >= 50: grade = "C"
    elif score >= 25: grade = "D"
    else:             grade = "F"
    return score, grade


# ── HTML report ────────────────────────────────────────────────────────────────

def _html_esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _render_html(report_data):
    """Return a self-contained HTML string for the given report."""
    score, grade = _compute_score(report_data)
    ts = report_data.get("timestamp", "")
    try:
        import datetime as _dt
        dt = _dt.datetime.fromisoformat(ts)
        ts_human = dt.strftime("%d %b %Y  %H:%M UTC")
    except Exception:
        ts_human = ts

    target = report_data.get("target", "localhost")

    # flatten findings
    all_findings = []
    for chk in report_data.get("checks", []):
        for f in chk.get("findings", []):
            all_findings.append({**f, "_check": chk.get("check", "")})

    counts = {}
    for f in all_findings:
        s = f.get("severity", "INFO")
        counts[s] = counts.get(s, 0) + 1

    # grade colour
    _gc = {"A": "#22a85c", "B": "#5ab033", "C": "#e69500", "D": "#d45400", "F": "#b22222"}
    grade_color = _gc.get(grade, "#888")

    # severity count pills
    pill_order = [("CRITICAL", "#b22222"), ("HIGH", "#c96a00"),
                  ("MEDIUM", "#c9a800"), ("REVIEW", "#777")]
    pills_html = ""
    for sev, bg in pill_order:
        n = counts.get(sev, 0)
        if n:
            pills_html += (
                f'<div style="text-align:center">'
                f'<div style="font-size:30px;font-weight:800;color:{bg}">{n}</div>'
                f'<div style="font-size:10px;font-weight:700;letter-spacing:1px;color:#888">{sev}</div>'
                f'</div>'
            )

    # ok checks (no findings, no error)
    ok_checks = [c["check"] for c in report_data.get("checks", [])
                 if not c.get("findings") and not c.get("error")]
    ok_html = ""
    if ok_checks:
        tags = "".join(
            f'<span style="background:#e8f5e9;color:#2e7d32;padding:3px 10px;'
            f'border-radius:3px;font-size:12px;font-weight:500;margin:3px 3px 0 0;'
            f'display:inline-block">{_html_esc(c)}</span>'
            for c in ok_checks
        )
        ok_html = (
            f'<div style="margin-top:28px">'
            f'<div style="font-size:11px;font-weight:700;letter-spacing:1.5px;'
            f'text-transform:uppercase;color:#888;margin-bottom:10px;padding-bottom:6px;'
            f'border-bottom:1px solid #e0e0e0">Passed checks</div>'
            f'{tags}</div>'
        )

    # findings cards grouped and sorted by severity
    sorted_findings = sorted(
        all_findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 9)
    )
    _badge_style = {
        "CRITICAL": "background:#b22222;color:#fff",
        "HIGH":     "background:#c96a00;color:#fff",
        "MEDIUM":   "background:#c9a800;color:#000",
        "REVIEW":   "background:#777;color:#fff",
        "INFO":     "background:#aaa;color:#000",
    }
    findings_html = ""
    for f in sorted_findings:
        sev = f.get("severity", "INFO")
        bs = _badge_style.get(sev, "background:#ccc;color:#000")
        fix_cmds = f.get("fix_cmds", [])
        cmds_html = ""
        if fix_cmds:
            cmds_html = '<div style="margin-top:8px">' + "".join(
                f'<code style="display:block;background:#1e1e1e;color:#9cdcfe;'
                f'padding:6px 10px;border-radius:3px;font-family:monospace;'
                f'font-size:12px;margin-top:4px">{_html_esc(c)}</code>'
                for c in fix_cmds
            ) + "</div>"
        findings_html += f"""
<details style="background:#fff;border:1px solid #e8e8e8;border-radius:4px;
                margin-bottom:6px;overflow:hidden">
  <summary style="display:flex;align-items:center;gap:10px;padding:11px 14px;
                  cursor:pointer;list-style:none">
    <span style="{bs};padding:2px 8px;border-radius:3px;font-size:11px;
                 font-weight:700;letter-spacing:0.5px;white-space:nowrap">{sev}</span>
    <span style="font-size:11px;color:#999;white-space:nowrap">{_html_esc(f.get('_check',''))}</span>
    <span style="font-weight:500;flex:1">{_html_esc(f.get('label',''))}</span>
  </summary>
  <div style="padding:2px 14px 12px;border-top:1px solid #f0f0f0">
    <p style="margin:8px 0 0;font-size:13px;color:#555">
      <strong>Why:</strong> {_html_esc(f.get('why',''))}
    </p>
    <p style="margin:6px 0 0;font-size:13px;color:#555">
      <strong>Fix:</strong> {_html_esc(f.get('fix',''))}
    </p>
    {cmds_html}
  </div>
</details>"""

    findings_section = (
        f'<div style="margin-bottom:28px">'
        f'<div style="font-size:11px;font-weight:700;letter-spacing:1.5px;'
        f'text-transform:uppercase;color:#888;margin-bottom:12px;padding-bottom:6px;'
        f'border-bottom:1px solid #e0e0e0">'
        f'Findings &mdash; {len(all_findings)} total</div>'
        f'{findings_html or "<p style=\'color:#22a85c;font-weight:600\'>No findings. Clean scan.</p>"}'
        f'</div>'
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Report — {_html_esc(target)}</title>
<style>
*,*::before,*::after{{box-sizing:border-box}}
body{{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
     font-size:14px;line-height:1.5;background:#f4f5f7;color:#1a1a1a}}
details summary::-webkit-details-marker{{display:none}}
details summary:hover{{background:#fafafa}}
@media print{{
  body{{background:#fff}}
  details{{open:true}}
  details:not([open]){{display:block}}
  details:not([open]) .finding-body{{display:block}}
}}
</style>
</head>
<body>
<div style="background:#111;color:#fff;padding:18px 40px;
            display:flex;justify-content:space-between;align-items:center">
  <div style="font-size:17px;letter-spacing:2px;font-weight:700">EXPOSURE CHECKER</div>
  <div style="text-align:right;font-size:12px;color:#888;line-height:1.9">
    Security Audit Report<br>
    Target: {_html_esc(target)}<br>
    {_html_esc(ts_human)}
  </div>
</div>

<div style="background:#fff;border-bottom:2px solid #e8e8e8;padding:22px 40px;
            display:flex;align-items:center;gap:32px">
  <div style="font-size:80px;font-weight:900;line-height:1;color:{grade_color}">{grade}</div>
  <div>
    <div style="font-size:32px;font-weight:700">{score}<span style="font-size:16px;
         color:#888;font-weight:400">/100</span></div>
    <div style="font-size:12px;color:#888;margin-top:2px">Risk Score</div>
  </div>
  <div style="display:flex;gap:24px;margin-left:auto">
    {pills_html}
  </div>
</div>

<div style="max-width:900px;margin:0 auto;padding:28px 20px">
  {findings_section}
  {ok_html}
  <div style="text-align:center;padding:20px 0 8px;font-size:11px;color:#bbb;
              border-top:1px solid #e8e8e8;margin-top:20px">
    Generated by Exposure Checker &mdash; self-hosted &mdash;
    your data never leaves this machine
  </div>
</div>
</body>
</html>"""


# ── Scan history ──────────────────────────────────────────────────────────────

_EC_DATA_DIR  = os.path.expanduser("~/.local/share/exposure-checker")
_HISTORY_DIR  = os.path.join(_EC_DATA_DIR, "history")
_ACCEPTED_FILE = os.path.join(_EC_DATA_DIR, "accepted_risks.json")


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

def run_headless_scan(tabs: list = None, notify: bool = True) -> None:
    """Run scans headlessly, save history, optionally send desktop notification."""
    if tabs is None:
        tabs = ["security"]
    results = []
    for tab in tabs:
        reporter = _Reporter()
        try:
            if tab == "security":
                run_port_scan(reporter, "127.0.0.1", "127.0.0.1", 1.0)
                audit_ssh(reporter)
                check_firewall(reporter)
                check_listeners(reporter)
                check_world_writable(reporter)
                check_suid(reporter)
                check_cron(reporter)
                check_packages(reporter)
                check_kernel_hardening(reporter)
                check_sensitive_perms(reporter)
                check_user_accounts(reporter)
                check_docker_socket(reporter)
            elif tab == "antivirus":
                check_auth_log(reporter)
                check_malware(reporter)
            elif tab == "performance":
                check_startup(reporter)
                check_power_settings(reporter)
                check_gpu_settings(reporter)
            elif tab == "protection":
                check_protection_hardening(reporter)
            elif tab == "cleaner":
                check_system_cleaner(reporter)
                check_startup(reporter)
        except Exception:
            continue
        score, grade = _compute_score(reporter._data)
        counts: dict = {}
        for chk in reporter._data.get("checks", []):
            for f in chk.get("findings", []):
                s = f.get("severity", "INFO")
                counts[s] = counts.get(s, 0) + 1
        save_scan_history(tab, score, grade, counts)
        results.append((tab, score, grade, counts))
    if notify and results:
        _notify_desktop(results)


def _notify_desktop(results: list) -> None:
    worst = min(results, key=lambda x: x[1])
    _, score, grade, counts = worst
    n_crit = counts.get("CRITICAL", 0)
    if n_crit > 0 or grade == "F":
        urgency = "critical"
        title   = f"Gull: Action required — Grade {grade}"
        body    = (f"{n_crit} critical issue(s) found. Open Exposure Checker to fix."
                   if n_crit else f"Score {score}/100. Immediate attention needed.")
    elif grade in ("D", "C"):
        urgency = "normal"
        title   = f"Gull: Security check — Grade {grade}"
        body    = f"Score {score}/100. Some issues need attention."
    else:
        urgency = "low"
        title   = f"Gull: All clear — Grade {grade}"
        body    = f"Score {score}/100. No critical issues found."

    if _OS == "Linux":
        try:
            subprocess.run(
                ["notify-send", "--urgency", urgency,
                 "--app-name", "Exposure Checker", title, body],
                timeout=5, capture_output=True,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    elif _OS == "Darwin":
        script = (f'display notification "{body}" '
                  f'with title "Exposure Checker" subtitle "{title}"')
        try:
            subprocess.run(["osascript", "-e", script], timeout=5, capture_output=True)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    elif _OS == "Windows":
        # Use PowerShell toast notification
        ps_cmd = (
            f"[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, "
            f"ContentType=WindowsRuntime] | Out-Null; "
            f"$t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent("
            f"[Windows.UI.Notifications.ToastTemplateType]::ToastText02); "
            f"$t.GetElementsByTagName('text')[0].AppendChild($t.CreateTextNode('{title}')) | Out-Null; "
            f"$t.GetElementsByTagName('text')[1].AppendChild($t.CreateTextNode('{body}')) | Out-Null; "
            f"$n = [Windows.UI.Notifications.ToastNotification]::new($t); "
            f"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('ExposureChecker').Show($n)"
        )
        try:
            _ps(ps_cmd, timeout=5)
        except Exception:
            pass


# ── SSH remote scan ───────────────────────────────────────────────────────────

def run_remote_scan(target: str, reporter: "_Reporter") -> None:
    """Upload this script to user@host via SSH, run a full JSON scan, import results."""
    if "@" not in target:
        reporter.begin("REMOTE SCAN", f"Target: {target}")
        reporter.error("Invalid SSH target — expected user@host or user@host:port")
        return

    user, rest = target.split("@", 1)
    port = 22
    if ":" in rest:
        host, p = rest.rsplit(":", 1)
        try:
            port = int(p)
        except ValueError:
            host = rest
    else:
        host = rest

    reporter.begin("REMOTE SCAN", f"Target: {user}@{host}:{port}")

    try:
        import paramiko as _pm
    except ImportError:
        reporter.error("paramiko not installed — run: pip install paramiko")
        return

    script = os.path.abspath(__file__)
    try:
        client = _pm.SSHClient()
        client.set_missing_host_key_policy(_pm.AutoAddPolicy())
        client.connect(host, port=port, username=user, timeout=20,
                        look_for_keys=True, allow_agent=True)

        sftp = client.open_sftp()
        sftp.put(script, "/tmp/.ec_remote_scan.py")
        sftp.close()

        cmd = ("python3 /tmp/.ec_remote_scan.py --full-audit --json 2>/dev/null"
               "; rm -f /tmp/.ec_remote_scan.py")
        _, stdout, _ = client.exec_command(cmd, timeout=120)
        raw = stdout.read().decode("utf-8", errors="replace")
        client.close()

        data = json.loads(raw)
        for chk in data.get("checks", []):
            for f in chk.get("findings", []):
                reporter.finding(
                    f.get("severity", "INFO"),
                    f.get("label", ""),
                    f.get("why", ""),
                    f.get("fix", ""),
                )
        reporter.end(f"Remote scan of {host} complete.")
    except json.JSONDecodeError:
        reporter.error("Remote scan returned no parseable output — check SSH access")
    except Exception as exc:
        reporter.error(f"Remote scan failed: {type(exc).__name__}: {exc}")


# ── PDF report export ─────────────────────────────────────────────────────────

def generate_pdf_report(report_data: dict, path: str) -> str:
    """Generate a professional PDF report. Returns error string or empty string."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable,
        )
        from reportlab.lib.enums import TA_CENTER
    except ImportError:
        return "reportlab not installed — run: pip install reportlab"

    score, grade = _compute_score(report_data)
    ts  = report_data.get("timestamp", "")
    try:
        dt      = datetime.datetime.fromisoformat(ts)
        ts_human = dt.strftime("%d %b %Y  %H:%M UTC")
    except Exception:
        ts_human = ts

    grade_hex = {
        "A": "#34c96a", "B": "#00b4d8", "C": "#e8c13a",
        "D": "#f5922e", "F": "#f25757",
    }.get(grade, "#6b7786")

    sev_hex = {
        "CRITICAL": "#f25757", "HIGH": "#f5922e",
        "MEDIUM": "#e8c13a",   "REVIEW": "#6b7786", "INFO": "#888888",
    }

    doc  = SimpleDocTemplate(path, pagesize=A4, topMargin=2*cm,
                              bottomMargin=2*cm, leftMargin=2.5*cm,
                              rightMargin=2.5*cm)
    story = []

    hdr_style = ParagraphStyle("hdr", fontSize=22, fontName="Helvetica-Bold",
                                 spaceAfter=4, alignment=TA_CENTER)
    sub_style = ParagraphStyle("sub", fontSize=10, fontName="Helvetica",
                                 textColor=colors.HexColor("#555555"),
                                 spaceAfter=4, alignment=TA_CENTER)
    grade_style = ParagraphStyle("grade", fontSize=48, fontName="Helvetica-Bold",
                                  textColor=colors.HexColor(grade_hex),
                                  spaceAfter=2, alignment=TA_CENTER)
    score_style = ParagraphStyle("score", fontSize=14, fontName="Helvetica",
                                  textColor=colors.HexColor("#333333"),
                                  spaceAfter=2, alignment=TA_CENTER)
    sec_style   = ParagraphStyle("sec", fontSize=13, fontName="Helvetica-Bold",
                                  textColor=colors.HexColor("#111111"),
                                  spaceBefore=14, spaceAfter=6)
    body_style  = ParagraphStyle("body", fontSize=9, fontName="Helvetica",
                                  leading=13, textColor=colors.HexColor("#222222"),
                                  spaceAfter=3)
    muted_style = ParagraphStyle("muted", fontSize=8, fontName="Helvetica",
                                  textColor=colors.HexColor("#666666"),
                                  leading=12, spaceAfter=6)

    story.append(Spacer(1, 0.8*cm))
    story.append(Paragraph("Exposure Checker", hdr_style))
    story.append(Paragraph("Security Scan Report — Gull", sub_style))
    story.append(Paragraph(ts_human, sub_style))
    story.append(Spacer(1, 0.6*cm))
    story.append(HRFlowable(width="100%", thickness=1,
                              color=colors.HexColor("#dddddd")))
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph(grade, grade_style))
    story.append(Paragraph(f"Score: {score} / 100", score_style))
    story.append(Spacer(1, 0.6*cm))
    story.append(HRFlowable(width="100%", thickness=1,
                              color=colors.HexColor("#dddddd")))

    # Collect all findings sorted by severity
    all_findings = []
    for chk in report_data.get("checks", []):
        for f in chk.get("findings", []):
            all_findings.append((chk.get("check", ""), f))

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "REVIEW": 3, "INFO": 4}
    all_findings.sort(key=lambda x: sev_order.get(x[1].get("severity", ""), 5))

    if not all_findings:
        story.append(Spacer(1, 0.5*cm))
        story.append(Paragraph("No findings — system is clean.", body_style))
    else:
        story.append(Paragraph("Findings", sec_style))
        cur_sev = None
        for chk_name, f in all_findings:
            sev = f.get("severity", "INFO")
            if sev != cur_sev:
                cur_sev = sev
                story.append(Spacer(1, 0.3*cm))
                col = colors.HexColor(sev_hex.get(sev, "#888888"))
                tbl = Table([[Paragraph(sev, ParagraphStyle(
                    "sh", fontSize=8, fontName="Helvetica-Bold",
                    textColor=colors.white))]],
                    colWidths=[2*cm])
                tbl.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), col),
                    ("TOPPADDING",    (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                ]))
                story.append(tbl)

            label = f.get("label", "")
            why   = f.get("why", "")
            fix   = f.get("fix", "")

            row_data = [[
                Paragraph(f"<b>{_html_esc(label)}</b>", body_style),
                Paragraph(_html_esc(chk_name), muted_style),
            ]]
            row_tbl = Table(row_data, colWidths=[10*cm, 5*cm])
            row_tbl.setStyle(TableStyle([
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ("LEFTPADDING",   (0, 0), (0, -1), 10),
                ("LINEBELOW",     (0, 0), (-1, 0),
                 0.3, colors.HexColor("#eeeeee")),
            ]))
            story.append(row_tbl)
            if why:
                story.append(Paragraph(_html_esc(why), muted_style))
            if fix:
                story.append(Paragraph(
                    f"<font color='#00b4d8'>Fix: {_html_esc(fix)}</font>",
                    muted_style))

    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width="100%", thickness=0.5,
                              color=colors.HexColor("#dddddd")))
    story.append(Paragraph("Generated by Exposure Checker (self-hosted) — Gull",
                            muted_style))

    try:
        doc.build(story)
        return ""
    except Exception as exc:
        return str(exc)


# ── Snapshots ────────────────────────────────────────────────────────────────

_SNAPSHOT_DIR = os.path.expanduser("~/.local/share/exposure-checker/snapshots")
_SNAPSHOT_CAPTURED_FILES = [
    "/etc/ssh/sshd_config",
    "/etc/ld.so.preload",
]


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

def _run_fix_cmd(cmd):
    """Run a single shell fix command. Returns (returncode, combined_output)."""
    try:
        if _OS == "Windows":
            no_window = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            # $ErrorActionPreference='Stop' makes cmdlet failures non-zero exit codes
            full_cmd = f"$ErrorActionPreference = 'Stop'; {cmd}"
            result = subprocess.run(
                ["powershell", "-NonInteractive", "-NoProfile", "-Command", full_cmd],
                capture_output=True, text=True, errors="replace", timeout=120,
                creationflags=no_window,
            )
            return result.returncode, (result.stdout + result.stderr).strip()
        result = subprocess.run(
            cmd, shell=True, text=True, errors="replace",
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=60,
        )
        return result.returncode, result.stdout.strip()
    except subprocess.TimeoutExpired:
        return 1, "timed out"
    except Exception as e:
        return 1, str(e)


def _collect_fixable(report_data):
    """Return flat list of (check, label, fix_cmds) for all fixable findings."""
    items = []
    for check in report_data.get("checks", []):
        for f in check.get("findings", []):
            cmds = f.get("fix_cmds", [])
            if cmds:
                items.append({
                    "check": check["check"],
                    "label": f["label"],
                    "severity": f["severity"],
                    "fix_cmds": cmds,
                })
    return items


def _print_remediation_menu(items):
    width = 66
    print("=" * width)
    print("  FIXABLE FINDINGS")
    print("=" * width)
    if not items:
        print("  No findings with automated fixes in this report.")
        print("=" * width)
        return
    for i, item in enumerate(items, 1):
        sev = item["severity"]
        print(f"\n  [{i}] [{sev}]  {item['check']} / {item['label']}")
        for cmd in item["fix_cmds"]:
            print(f"       $ {cmd}")
    print()
    print("-" * width)


def _remediate_main(argv):
    parser = argparse.ArgumentParser(
        prog="exposure-checker remediate",
        description="Apply automated fixes from a saved scan report.\n\n"
                    "WARNING: Only run this on reports generated by this tool on "
                    "systems you own. Fix commands are executed with your current "
                    "privileges — use sudo if root access is required.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("report", help="JSON report file produced by --output.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show fix commands without executing them.")
    parser.add_argument("--all", dest="fix_all", action="store_true",
                        help="Apply all available fixes.")
    parser.add_argument("--item", metavar="N", type=int, action="append",
                        dest="items", default=[],
                        help="Apply fix for finding number N (repeatable).")
    parser.add_argument("--yes", action="store_true",
                        help="Skip per-fix confirmation prompts.")
    args = parser.parse_args(argv)

    data, err = _load_report(args.report)
    if err:
        print(f"[!] {err}", file=sys.stderr)
        sys.exit(1)

    fixable = _collect_fixable(data)
    _print_remediation_menu(fixable)

    if not fixable or args.dry_run:
        return

    # Determine which items to fix
    if args.fix_all:
        selected = list(range(len(fixable)))
    elif args.items:
        selected = []
        for n in args.items:
            if 1 <= n <= len(fixable):
                selected.append(n - 1)
            else:
                print(f"[!] Item {n} out of range (1–{len(fixable)}).", file=sys.stderr)
                sys.exit(1)
    else:
        # Interactive menu
        try:
            raw = input("Enter item numbers to fix (e.g. 1,3), 'all', or 'q' to quit: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if raw.lower() in ("q", "quit", ""):
            return
        if raw.lower() == "all":
            selected = list(range(len(fixable)))
        else:
            selected = []
            for part in raw.replace(" ", "").split(","):
                try:
                    n = int(part)
                except ValueError:
                    print(f"[!] Invalid input: {part!r}", file=sys.stderr)
                    sys.exit(1)
                if not (1 <= n <= len(fixable)):
                    print(f"[!] Item {n} out of range (1–{len(fixable)}).", file=sys.stderr)
                    sys.exit(1)
                selected.append(n - 1)

    # Execute
    failed = 0
    for idx in selected:
        item = fixable[idx]
        print(f"\n── Fixing [{item['severity']}] {item['label']} ──")
        for cmd in item["fix_cmds"]:
            print(f"  $ {cmd}")
            if not args.yes:
                try:
                    confirm = input("  Run this command? [y/N] ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print()
                    return
                if confirm not in ("y", "yes"):
                    print("  Skipped.")
                    continue
            rc, out = _run_fix_cmd(cmd)
            if rc == 0:
                print(f"  ✓ OK" + (f": {out}" if out else ""))
            else:
                print(f"  ✗ FAILED (exit {rc})" + (f": {out}" if out else ""))
                failed += 1

    if failed:
        print(f"\n[!] {failed} command(s) failed.", file=sys.stderr)
        sys.exit(1)
    else:
        print("\n[+] All selected fixes applied.")


# ── Email notification ────────────────────────────────────────────────────────

_SMTP_CONFIG_TEMPLATE = """\
[smtp]
host     = smtp.example.com
port     = 587
user     = you@example.com
password = yourpassword
from     = you@example.com
"""


def _load_smtp_config():
    """Return smtp config dict or raise ValueError with a human message."""
    import configparser
    if not os.path.exists(_SMTP_CONFIG_PATH):
        raise ValueError(
            f"SMTP config not found. Run: exposure-checker schedule install --email EMAIL\n"
            f"Then edit {_SMTP_CONFIG_PATH} with your SMTP credentials."
        )
    cfg = configparser.ConfigParser()
    cfg.read(_SMTP_CONFIG_PATH)
    if "smtp" not in cfg:
        raise ValueError(f"[smtp] section missing in {_SMTP_CONFIG_PATH}")
    s = cfg["smtp"]
    required = ("host", "port", "user", "password", "from")
    missing = [k for k in required if not s.get(k)]
    if missing:
        raise ValueError(f"Missing SMTP keys in {_SMTP_CONFIG_PATH}: {', '.join(missing)}")
    return s


def _send_notification(to_email, report_data):
    """Send a scan summary email. Raises on failure."""
    import smtplib
    import email.message

    smtp = _load_smtp_config()
    score, grade = _compute_score(report_data)

    counts = {}
    for chk in report_data.get("checks", []):
        for f in chk.get("findings", []):
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1

    lines = [
        f"Exposure Checker Scan Report",
        f"Target   : {report_data.get('target', 'localhost')}",
        f"Time     : {report_data.get('timestamp', '')}",
        f"Score    : {score}/100  Grade: {grade}",
        "",
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "REVIEW", "INFO"):
        n = counts.get(sev, 0)
        if n:
            lines.append(f"  {sev:<10} {n}")
    lines.append("")
    if counts.get("CRITICAL") or counts.get("HIGH"):
        lines.append("Action required: review findings and run remediation.")
    else:
        lines.append("No critical or high findings detected.")
    lines.append("")
    lines.append("-- Exposure Checker (self-hosted) --")

    msg = email.message.EmailMessage()
    msg["Subject"] = f"[exposure-checker] Score {score}/100 Grade {grade} — {report_data.get('target','localhost')}"
    msg["From"] = smtp["from"]
    msg["To"] = to_email
    msg.set_content("\n".join(lines))

    port = int(smtp["port"])
    host = smtp["host"]
    user = smtp["user"]
    password = smtp["password"]

    with smtplib.SMTP(host, port) as conn:
        conn.ehlo()
        conn.starttls()
        conn.login(user, password)
        conn.send_message(msg)


# ── Scheduled scan ────────────────────────────────────────────────────────────

_CRON_MARKER = "# exposure-checker-schedule"


def _schedule_main(argv):
    parser = argparse.ArgumentParser(
        prog="exposure-checker schedule",
        description="Install or remove a scheduled weekly scan via user crontab.",
    )
    sub = parser.add_subparsers(dest="action", required=True)

    p_install = sub.add_parser("install", help="Add weekly cron job.")
    p_install.add_argument("--email", metavar="EMAIL",
                           help="Send scan summary to this address after each run.")
    p_install.add_argument("--cron", metavar="EXPR", default="0 6 * * 1",
                           help="Cron schedule expression (default: Mon 06:00).")

    sub.add_parser("remove", help="Remove the scheduled cron job.")
    sub.add_parser("status", help="Show whether a scheduled job is installed.")

    args = parser.parse_args(argv)

    if args.action == "status":
        jobs = _read_ec_cron_jobs()
        if jobs:
            print("[*] Scheduled job is installed:")
            for j in jobs:
                print(f"    {j}")
        else:
            print("[*] No scheduled job found.")
        return

    if args.action == "remove":
        _write_crontab(_strip_ec_lines(_read_full_crontab()))
        print("[*] Scheduled job removed.")
        return

    # install
    exe = shlex.quote(sys.executable)
    cmd = f"{exe} -m exposure_checker --full-audit --save-baseline"
    if args.email:
        _validate_email(args.email)
        cmd += f" --email {args.email}"
        _ensure_smtp_config()
    cron_line = f"{args.cron} {cmd}  {_CRON_MARKER}"

    existing = _read_full_crontab()
    cleaned  = _strip_ec_lines(existing)
    _write_crontab(cleaned + [cron_line])
    print(f"[*] Scheduled job installed: {args.cron}")
    if args.email:
        print(f"[*] Notifications → {args.email}")
        print(f"[!] Edit {_SMTP_CONFIG_PATH} with your SMTP credentials before the first run.")


def _read_full_crontab():
    if _OS == "Windows":
        return []
    result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    if result.returncode != 0:
        return []
    return result.stdout.splitlines()


def _strip_ec_lines(lines):
    return [l for l in lines if _CRON_MARKER not in l]


def _read_ec_cron_jobs():
    return [l for l in _read_full_crontab() if _CRON_MARKER in l]


def _write_crontab(lines):
    content = "\n".join(lines) + "\n"
    result = subprocess.run(["crontab", "-"], input=content, text=True, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(f"crontab write failed: {result.stderr.strip()}")


def _validate_email(addr):
    if "@" not in addr or addr.startswith("@") or addr.endswith("@"):
        raise SystemExit(f"[!] Invalid email address: {addr}")


def _ensure_smtp_config():
    if os.path.exists(_SMTP_CONFIG_PATH):
        return
    parent = os.path.dirname(_SMTP_CONFIG_PATH)
    os.makedirs(parent, exist_ok=True)
    with open(_SMTP_CONFIG_PATH, "w") as fh:
        fh.write(_SMTP_CONFIG_TEMPLATE)
    os.chmod(_SMTP_CONFIG_PATH, 0o600)


# ── UI-managed schedule (crontab-backed) ─────────────────────────────────────

def load_schedule() -> dict:
    """Return persisted schedule config, or safe defaults."""
    try:
        with open(_SCHEDULE_FILE) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {"enabled": False, "hour": 9, "minute": 0, "tabs": ["security"]}


def save_schedule(sched: dict) -> None:
    d = os.path.dirname(_SCHEDULE_FILE)
    os.makedirs(d, exist_ok=True)
    with open(_SCHEDULE_FILE, "w") as fh:
        json.dump(sched, fh, indent=2)


def install_schedule(sched: dict) -> tuple:
    """Write/remove a schedule entry for the headless scan. Returns (ok, errmsg)."""
    if _OS == "Darwin":
        return _install_schedule_macos(sched)
    if _OS == "Windows":
        return _install_schedule_windows(sched)
    # Linux: existing crontab approach
    try:
        # _self_invocation() handles the frozen (PyInstaller) app, whose
        # __file__ points into a temp dir that vanishes when the app exits.
        invoke  = " ".join(shlex.quote(p) for p in _self_invocation())
        tabs    = " ".join(shlex.quote(t) for t in sched.get("tabs", ["security"]))
        hour    = int(sched.get("hour", 9))
        minute  = int(sched.get("minute", 0))
        existing = _read_full_crontab()
        cleaned  = _strip_ec_lines(existing)
        if sched.get("enabled"):
            cmd  = f"{invoke} headless --tabs {tabs}"
            line = f"{minute} {hour} * * * {cmd}  {_CRON_MARKER}"
            _write_crontab(cleaned + [line])
        else:
            _write_crontab(cleaned)
        return (True, "")
    except Exception as exc:
        return (False, str(exc))


def _install_schedule_macos(sched: dict) -> tuple:
    """Install a launchd user agent for scheduled scans."""
    try:
        label  = "com.exposurechecker.scan"
        plist_dir  = os.path.expanduser("~/Library/LaunchAgents")
        plist_path = os.path.join(plist_dir, f"{label}.plist")
        os.makedirs(plist_dir, exist_ok=True)
        # Unload existing
        subprocess.run(["launchctl", "unload", plist_path],
                       capture_output=True, timeout=5)
        if not sched.get("enabled"):
            try:
                os.unlink(plist_path)
            except OSError:
                pass
            return (True, "")
        hour   = int(sched.get("hour", 9))
        minute = int(sched.get("minute", 0))
        tabs   = sched.get("tabs", ["security"])
        invoke = _self_invocation()  # frozen-app safe
        plist  = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    {''.join(f'<string>{p}</string>' for p in invoke)}
    <string>headless</string>
    <string>--tabs</string>
    {''.join(f'<string>{t}</string>' for t in tabs)}
  </array>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key><integer>{hour}</integer>
    <key>Minute</key><integer>{minute}</integer>
  </dict>
  <key>RunAtLoad</key><false/>
</dict>
</plist>"""
        with open(plist_path, "w") as fh:
            fh.write(plist)
        subprocess.run(["launchctl", "load", plist_path],
                       capture_output=True, timeout=5)
        return (True, "")
    except Exception as exc:
        return (False, str(exc))


def _install_schedule_windows(sched: dict) -> tuple:
    """Install a Windows Task Scheduler entry for scheduled scans."""
    try:
        task_name = "ExposureCheckerScan"
        # Remove existing
        _ps(f'Unregister-ScheduledTask -TaskName "{task_name}" -Confirm:$false -ErrorAction SilentlyContinue')
        if not sched.get("enabled"):
            return (True, "")
        hour   = int(sched.get("hour", 9))
        minute = int(sched.get("minute", 0))
        tabs   = " ".join(sched.get("tabs", ["security"]))
        invoke = _self_invocation()  # frozen-app safe
        exe    = invoke[0]
        arg_parts = [f'\\"{p}\\"' for p in invoke[1:]] + ["headless", "--tabs", tabs]
        arg_str   = " ".join(arg_parts)
        cmd = (
            f'$action = New-ScheduledTaskAction -Execute "{exe}" '
            f'-Argument "{arg_str}"; '
            f'$trigger = New-ScheduledTaskTrigger -Daily -At "{hour:02d}:{minute:02d}"; '
            f'Register-ScheduledTask -TaskName "{task_name}" '
            f'-Action $action -Trigger $trigger -RunLevel Highest -Force'
        )
        out, rc = _ps(cmd, timeout=30)
        if rc != 0:
            return (False, out.strip() or "schtasks registration failed")
        return (True, "")
    except Exception as exc:
        return (False, str(exc))


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "diff":
        _diff_main(sys.argv[2:])
        return

    if len(sys.argv) > 1 and sys.argv[1] == "remediate":
        _remediate_main(sys.argv[2:])
        return

    if len(sys.argv) > 1 and sys.argv[1] == "headless":
        import argparse as _ap
        p = _ap.ArgumentParser(prog="exposure-checker headless")
        p.add_argument("--tabs", nargs="+",
                       default=["security"],
                       choices=["security", "antivirus", "performance",
                                "protection", "cleaner"])
        p.add_argument("--no-notify", action="store_true")
        a = p.parse_args(sys.argv[2:])
        run_headless_scan(a.tabs, notify=not a.no_notify)
        return

    if len(sys.argv) > 1 and sys.argv[1] == "schedule":
        _schedule_main(sys.argv[2:])
        return

    parser = argparse.ArgumentParser(
        prog="exposure-checker",
        description="Scan a machine YOU OWN for risky open ports and weak config.")
    parser.add_argument("--version", action="version", version=f"exposure-checker {__version__}")
    parser.add_argument("target", nargs="?", default="127.0.0.1",
                        help="IP or hostname to scan (default: your own machine).")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Per-port timeout in seconds (default: 1.0).")

    # Local checks
    parser.add_argument("--ssh-audit", action="store_true",
                        help="Audit /etc/ssh/sshd_config for weak settings.")
    parser.add_argument("--ssh-audit-only", action="store_true",
                        help="Run only the SSH audit; skip the port scan.")
    parser.add_argument("--check-firewall", action="store_true",
                        help="Check whether a firewall is active.")
    parser.add_argument("--check-listeners", action="store_true",
                        help="List TCP services bound to non-localhost interfaces.")
    parser.add_argument("--check-world-writable", action="store_true",
                        help="Find world-writable files in standard system directories.")
    parser.add_argument("--check-suid", action="store_true",
                        help="Find SUID/SGID binaries in standard binary paths.")
    parser.add_argument("--check-cron", action="store_true",
                        help="Audit cron jobs for world-writable script paths.")
    parser.add_argument("--check-packages", action="store_true",
                        help="Check for pending OS package updates (apt/dnf/yum).")
    parser.add_argument("--check-kernel", action="store_true",
                        help="Audit sysctl kernel hardening parameters.")
    parser.add_argument("--check-sensitive-perms", action="store_true",
                        help="Check permissions on /etc/shadow, /etc/sudoers, SSH host keys, etc.")
    parser.add_argument("--check-user-accounts", action="store_true",
                        help="Check for extra UID-0 accounts and empty passwords.")
    parser.add_argument("--check-docker", action="store_true",
                        help="Check Docker socket permissions.")
    parser.add_argument("--check-auth", action="store_true",
                        help="Scan auth log for SSH brute-force and sudo failures "
                             "(requires read access to /var/log/auth.log).")
    parser.add_argument("--check-malware", action="store_true",
                        help="Malware scan: ClamAV signatures (if installed) + heuristic "
                             "indicators (temp executables, suspicious processes, rootkit "
                             "markers, known-bad script patterns).")
    parser.add_argument("--malware-paths", nargs="+", metavar="PATH",
                        help="Override default paths for the ClamAV scan "
                             f"(default: {', '.join(_AV_CLAMAV_PATHS)}).")
    parser.add_argument("--check-startup", action="store_true",
                        help="Audit programs configured to launch at boot/login.")
    parser.add_argument("--check-cleaner", action="store_true",
                        help="Scan for reclaimable disk space (caches, temp junk, debris).")
    parser.add_argument("--check-power", action="store_true",
                        help="Audit power settings that affect gaming performance and latency.")
    parser.add_argument("--check-gpu", action="store_true",
                        help="Audit GPU, game capture, and driver-related gaming settings.")
    parser.add_argument("--check-protection", action="store_true",
                        help="Audit extra local protection controls for ransomware and remote access.")
    parser.add_argument("--gamer-audit", action="store_true",
                        help="Run the local gamer optimization suite: startup, power, GPU, "
                             "cleaner, and extra protection checks.")
    parser.add_argument("--full-audit", action="store_true",
                        help="Run all local checks (port scan + SSH + firewall + "
                             "listeners + world-writable + SUID + cron + packages + "
                             "kernel + sensitive-perms + user-accounts + docker + "
                             "auth + malware + cleaner + startup + power + GPU + protection).")

    # Remote / tool-dependent checks
    parser.add_argument("--tls-check", metavar="HOST[:PORT]",
                        help="Check TLS certificate expiry (default port: 443).")
    parser.add_argument("--trivy-scan", nargs="?", const="ALL", metavar="IMAGE[:TAG]",
                        help="CVE-scan local Docker images with Trivy. "
                             "Omit IMAGE to scan all local images.")

    # Output format
    parser.add_argument("--json", action="store_true",
                        help="Emit findings as JSON instead of human-readable text.")
    parser.add_argument("--output", metavar="FILE",
                        help="Write the full report to FILE (.json or .html auto-detected).")
    parser.add_argument("--fail-on", metavar="SEVERITY",
                        choices=["critical", "high", "medium", "review", "info"],
                        type=str.lower,
                        help="Exit with status 1 if any finding is at or above SEVERITY "
                             "(or any NEW finding when used with --diff-baseline).")
    parser.add_argument("--profile",
                        choices=list(_PROFILE_MAP),
                        metavar="PROFILE",
                        help="Check compliance against a named profile and exit 1 if any "
                             "required control fails.  Choices: "
                             + ", ".join(_PROFILE_MAP) + ".  "
                             "Required checks for the profile are enabled automatically.")
    parser.add_argument("--email", metavar="ADDRESS",
                        help="Email scan summary to ADDRESS after the scan completes. "
                             f"SMTP credentials must be set in {_SMTP_CONFIG_PATH}.")

    # Baseline
    parser.add_argument("--baseline-file", metavar="FILE", default=_DEFAULT_BASELINE,
                        help=f"Path to the baseline file (default: {_DEFAULT_BASELINE}).")
    parser.add_argument("--save-baseline", action="store_true",
                        help="Save this scan as the new baseline.")
    parser.add_argument("--diff-baseline", action="store_true",
                        help="Diff this scan against the saved baseline and show changes.")

    args = parser.parse_args()

    # Auto-enable required checks for the chosen compliance profile
    if args.profile:
        for flag in _PROFILE_CHECKS.get(args.profile, []):
            if not getattr(args, flag, False):
                setattr(args, flag, True)

    reporter = _Reporter(json_mode=args.json)

    if not args.json:
        print("=" * 66)
        print("  EXPOSURE CHECKER")
        print("  !  Only scan systems you own or are authorised to test.")
        print("=" * 66)

    if sys.platform == "win32":
        try:
            import ctypes as _ctypes
            _is_admin = bool(_ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            _is_admin = False
    else:
        _is_admin = (os.geteuid() == 0)

    _admin_flags = [
        "ssh_audit", "ssh_audit_only", "check_firewall", "check_listeners",
        "check_world_writable", "check_suid", "check_cron", "check_packages",
        "check_kernel", "check_sensitive_perms", "check_user_accounts",
        "check_docker", "check_auth", "check_malware", "check_startup",
        "check_cleaner", "check_power", "check_gpu", "check_protection",
        "full_audit", "gamer_audit",
    ]
    _needs_admin = any(getattr(args, flag, False) for flag in _admin_flags)

    if not _is_admin and _needs_admin:
        msg = (
            "[!] Administrator privileges required for a complete scan.\n"
            "    Some checks (auth log, kernel params, file permissions) will\n"
            "    be skipped or return incomplete results without them.\n"
        )
        if sys.platform == "win32":
            msg += "    Re-run in an elevated (Administrator) terminal."
        else:
            msg += f"    Re-run with: sudo {' '.join(sys.argv)}"
        if args.json:
            import json as _json
            print(_json.dumps({"error": "administrator_required", "detail": msg.strip()}))
        else:
            print(msg, file=sys.stderr)
        sys.exit(1)

    if not args.ssh_audit_only:
        ip, display = resolve_target(args.target)
        run_port_scan(reporter, ip, display, args.timeout)

    if args.ssh_audit or args.ssh_audit_only or args.full_audit:
        audit_ssh(reporter)

    if args.check_firewall or args.full_audit:
        check_firewall(reporter)

    if args.check_listeners or args.full_audit:
        check_listeners(reporter)

    if args.check_world_writable or args.full_audit:
        check_world_writable(reporter)

    if args.check_suid or args.full_audit:
        check_suid(reporter)

    if args.check_cron or args.full_audit:
        check_cron(reporter)

    if args.check_packages or args.full_audit:
        check_packages(reporter)

    if args.check_kernel or args.full_audit:
        check_kernel_hardening(reporter)

    if args.check_sensitive_perms or args.full_audit:
        check_sensitive_perms(reporter)

    if args.check_user_accounts or args.full_audit:
        check_user_accounts(reporter)

    if args.check_docker or args.full_audit:
        check_docker_socket(reporter)

    if args.check_auth or args.full_audit:
        check_auth_log(reporter)

    if args.check_malware or args.full_audit:
        check_malware(reporter, clamav_paths=args.malware_paths or None)

    if args.check_startup or args.full_audit or args.gamer_audit:
        check_startup(reporter)

    if args.check_cleaner or args.full_audit or args.gamer_audit:
        check_system_cleaner(reporter)

    if args.check_power or args.full_audit or args.gamer_audit:
        check_power_settings(reporter)

    if args.check_gpu or args.full_audit or args.gamer_audit:
        check_gpu_settings(reporter)

    if args.check_protection or args.full_audit or args.gamer_audit:
        check_protection_hardening(reporter)

    if args.tls_check:
        check_tls(reporter, args.tls_check)

    if args.trivy_scan is not None:
        scan_trivy(reporter, args.trivy_scan)

    score, grade = _compute_score(reporter._data)
    reporter._data["score"] = score
    reporter._data["grade"] = grade
    if not args.json:
        bar = "█" * (score // 5) + "░" * (20 - score // 5)
        counts: dict[str, int] = {}
        for chk in reporter._data.get("checks", []):
            for f in chk.get("findings", []):
                s = f.get("severity", "")
                counts[s] = counts.get(s, 0) + 1
        parts = [f"{counts[s]} {s}" for s in ("CRITICAL", "HIGH", "MEDIUM", "REVIEW", "INFO") if counts.get(s)]
        summary = "  " + " · ".join(parts) if parts else "  No findings"
        print(f"\n  Risk Score  {score}/100  [{bar}]  Grade: {grade}")
        print(summary)

    _profile_failed = False
    if args.profile:
        profile_name = _PROFILE_MAP[args.profile]
        required     = _COMPLIANCE_REQUIRED.get(profile_name, {})
        sev_rank     = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "REVIEW": 1, "INFO": 0}
        all_findings = [f for chk in reporter._data.get("checks", [])
                        for f in chk.get("findings", [])]
        failing: dict = {}
        for f in all_findings:
            chk_name = f.get("check", "").lower()
            sev      = f.get("severity", "INFO")
            for req_key, min_sev in required.items():
                if (req_key in chk_name
                        and sev_rank.get(sev, 0) >= sev_rank.get(min_sev, 0)
                        and req_key not in failing):
                    failing[req_key] = f.get("label", sev)
        n_pass  = len(required) - len(failing)
        n_total = len(required)
        pct     = int(100 * n_pass / n_total) if n_total else 100
        result  = "PASS" if pct == 100 else "FAIL"
        reporter._data["compliance"] = {
            "profile": profile_name, "passing": n_pass,
            "total": n_total, "pct": pct, "result": result,
            "failing": failing,
        }
        if not args.json:
            col_w = max((len(k) for k in required), default=10) + 2
            bar_p = "█" * (pct // 5) + "░" * (20 - pct // 5)
            print(f"\n  ─── {profile_name} " + "─" * max(0, 44 - len(profile_name)))
            for key, min_sev in required.items():
                status = "FAIL" if key in failing else "PASS"
                detail = f"  ← {failing[key]}" if key in failing else ""
                print(f"  {key:<{col_w}} {status}{detail}")
            print(f"\n  Compliance  {n_pass}/{n_total}  [{bar_p}]  {pct}%  {result}")
        _profile_failed = pct < 100

    if args.output:
        err = reporter.write_to(args.output)
        if err:
            print(f"[!] Could not write report to {args.output}: {err}.", file=sys.stderr)
        elif not args.json:
            print(f"[*] Report saved → {args.output}")

    if args.email:
        try:
            _send_notification(args.email, reporter._data)
            if not args.json:
                print(f"[*] Notification sent → {args.email}")
        except Exception as exc:
            print(f"[!] Email failed: {exc}", file=sys.stderr)

    if args.diff_baseline:
        b_data, err = _load_report(args.baseline_file)
        if err:
            print(
                f"[!] --diff-baseline: {err}. Run with --save-baseline first.",
                file=sys.stderr,
            )
        else:
            diff = diff_reports(b_data, reporter._data)
            if args.json:
                print(json.dumps({
                    "before": {
                        "file": args.baseline_file,
                        "timestamp": b_data.get("timestamp"),
                    },
                    "after": {
                        "file": "(current scan)",
                        "timestamp": reporter._data.get("timestamp"),
                    },
                    "new": [
                        {"check": c, "label": l, "severity": s}
                        for c, l, s in diff["new"]
                    ],
                    "resolved": [
                        {"check": c, "label": l, "severity": s}
                        for c, l, s in diff["resolved"]
                    ],
                    "changed": [
                        {"check": c, "label": l, "before": bv, "after": av}
                        for c, l, bv, av in diff["changed"]
                    ],
                }, indent=2))
            else:
                _print_diff(
                    args.baseline_file, "(current scan)",
                    b_data, reporter._data, diff,
                )
            if args.fail_on:
                threshold = SEVERITY_ORDER.get(args.fail_on.upper(), 9)
                triggered = [
                    (c, l, s) for c, l, s in diff["new"]
                    if SEVERITY_ORDER.get(s, 9) <= threshold
                ]
                if triggered:
                    if not args.json:
                        print(
                            f"\n[!] --fail-on {args.fail_on}: "
                            f"{len(triggered)} new finding(s) at or above "
                            f"{args.fail_on.upper()}."
                        )
                    sys.exit(1)
    else:
        reporter.dump_json()
        if args.fail_on:
            triggered = reporter.findings_at_or_above(args.fail_on)
            if triggered:
                if not args.json:
                    print(
                        f"\n[!] --fail-on {args.fail_on}: "
                        f"{len(triggered)} finding(s) at or above "
                        f"{args.fail_on.upper()}."
                    )
                sys.exit(1)

    if args.save_baseline:
        err = _save_baseline(args.baseline_file, reporter._data)
        if err:
            print(
                f"[!] Could not save baseline to {args.baseline_file}: {err}.",
                file=sys.stderr,
            )
        elif not args.json:
            print(f"\n[*] Baseline saved to {args.baseline_file}")

    if _profile_failed:
        if not args.json:
            n_fail = len(reporter._data.get("compliance", {}).get("failing", {}))
            print(
                f"\n[!] --profile {args.profile}: "
                f"{n_fail} required control(s) failing."
            )
        sys.exit(1)


if __name__ == "__main__":
    main()
