"""Email notifications, cron/Task Scheduler management, and headless schedule."""

import configparser
import datetime
import json
import os
import re
import shlex
import shutil
import smtplib
import socket
import subprocess
import sys

from ._core import _OS, _ps, _self_invocation, _SMTP_CONFIG_PATH, _SCHEDULE_FILE, _Reporter
from ._report import _compute_score

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

