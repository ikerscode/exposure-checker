"""Security checks: SSH, TLS, Trivy, firewall, listeners, SUID, cron, kernel hardening, permissions, user accounts, Docker, auth log, malware, packages."""

import datetime
import json
import os
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys

from .._core import (
    _OS, _ps, _ps_quote, _shell_quote, _truncate,
    RISKY_PORTS, SPECIAL, SEVERITY_ORDER,
    _CRYPTO_OK, _cx509,
    _NO_WINDOW,
)

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

# Ports that are Windows system components — can't be disabled without
# breaking the OS.  We downgrade them to REVIEW so they don't tank the score.
_WIN_SYSTEM_PORTS = {135}  # MS-RPC: required by Component Services / DCOM

# Fix commands for common Windows ports that CAN be closed.
_WIN_PORT_FIX_CMDS = {
    # Remote Desktop
    3389: [
        "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server'"
        " -Name fDenyTSConnections -Value 1",
        "Disable-NetFirewallRule -DisplayGroup 'Remote Desktop'",
    ],
    # NetBIOS over TCP/IP (disable on all adapters)
    139: [
        "Get-WmiObject Win32_NetworkAdapterConfiguration"
        " | ForEach-Object { $_.SetTcpipNetbios(2) }",
    ],
    # SMB file server — stop LanmanServer (Windows file/printer sharing)
    445: [
        "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
        "Stop-Service -Name LanmanServer -Force -ErrorAction SilentlyContinue",
        "Set-Service -Name LanmanServer -StartupType Disabled",
    ],
    # Telnet client feature
    23: [
        "Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart",
    ],
    # IIS FTP service
    21: [
        "Stop-Service -Name ftpsvc -Force -ErrorAction SilentlyContinue",
        "Set-Service -Name ftpsvc -StartupType Disabled -ErrorAction SilentlyContinue",
    ],
}


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
        # Windows system ports that cannot be disabled without breaking the OS
        # are downgraded to REVIEW so they don't prevent an A rating.
        if port in _WIN_SYSTEM_PORTS:
            severity = "REVIEW"
        fix_cmds = _WIN_PORT_FIX_CMDS.get(port)
        label = f"port {port}/{addr} [{proc_name}] — {svc}"
        pending.append((severity, label, why, fix, fix_cmds, {"port": port, "address": addr}))
    if not pending:
        reporter.ok("No high-risk externally-bound services found")
        reporter.end()
        return
    pending.sort(key=lambda f: SEVERITY_ORDER.get(f[0], 9))
    for severity, label, why, fix, fix_cmds, extra in pending:
        reporter.finding(severity, label, why, fix, fix_cmds=fix_cmds, **extra)
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


_AV_CLAMAV_PATHS  = ["/tmp", "/var/tmp", "/dev/shm"]
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


