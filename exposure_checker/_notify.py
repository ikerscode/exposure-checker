"""Headless scanning, desktop notifications, and remote SSH scans."""

import json
import os
import shutil
import socket
import subprocess
import sys

from ._core import _OS, _ps, _Reporter
from .checks.security import (
    audit_ssh, check_firewall, check_listeners, check_world_writable,
    check_suid, check_cron, check_packages, check_kernel_hardening,
    check_sensitive_perms, check_user_accounts, check_docker_socket,
    check_auth_log, check_malware,
)
from .checks.performance import (
    check_startup, check_power_settings, check_gpu_settings,
    check_protection_hardening, check_network_perf,
    check_memory_perf, check_system_resources,
)
from .checks.cleaner import check_system_cleaner
from .checks.benchmark import check_benchmark
from .checks.overclock import check_overclock
from .checks.portscan import run_port_scan
from ._report import _compute_score
from ._storage import save_scan_history

# Tabs that produce findings worth scanning/remediating (benchmark excluded —
# it has no fixes and is slow).
SCANNABLE_TABS = ["security", "antivirus", "performance", "protection",
                  "cleaner", "overclock"]


def scan_to_report(tab: str) -> dict:
    """Run one tab's scanners against the current system; return the report data.

    Shared by the headless scan and by `remediate` re-validation so the set of
    commands the two trust can never drift apart.
    """
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
            check_network_perf(reporter)
            check_memory_perf(reporter)
            check_system_resources(reporter)
        elif tab == "protection":
            check_protection_hardening(reporter)
        elif tab == "cleaner":
            check_system_cleaner(reporter)
        elif tab == "benchmark":
            check_benchmark(reporter)
        elif tab == "overclock":
            check_overclock(reporter)
    except Exception:
        pass
    return reporter._data


def run_headless_scan(tabs: list = None, notify: bool = True) -> None:
    """Run scans headlessly, save history, optionally send desktop notification."""
    if tabs is None:
        tabs = ["security"]
    results = []
    for tab in tabs:
        data = scan_to_report(tab)
        if not data.get("checks"):
            continue
        score, grade = _compute_score(data)
        counts: dict = {}
        for chk in data.get("checks", []):
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
        title   = f"Gullwing: Action required — Grade {grade}"
        body    = (f"{n_crit} critical issue(s) found. Open Gullwing to fix."
                   if n_crit else f"Score {score}/100. Immediate attention needed.")
    elif grade in ("D", "C"):
        urgency = "normal"
        title   = f"Gullwing: Security check — Grade {grade}"
        body    = f"Score {score}/100. Some issues need attention."
    else:
        urgency = "low"
        title   = f"Gullwing: All clear — Grade {grade}"
        body    = f"Score {score}/100. No critical issues found."

    if _OS == "Linux":
        try:
            subprocess.run(
                ["notify-send", "--urgency", urgency,
                 "--app-name", "Gullwing", title, body],
                timeout=5, capture_output=True,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    elif _OS == "Darwin":
        script = (f'display notification "{body}" '
                  f'with title "Gullwing" subtitle "{title}"')
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
            f"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Gullwing').Show($n)"
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

