"""Cleaner checks: browser cache, dev caches, OS temp files, disk debris."""

import datetime
import json
import os
import re
import shlex
import shutil
import glob
import socket
import ssl
import subprocess
import sys
import time

from .._core import (
    _OS, _ps, _ps_quote, _shell_quote, _truncate,
    RISKY_PORTS, SPECIAL, SEVERITY_ORDER,
    _CRYPTO_OK, _cx509,
    _NO_WINDOW,
)

# ── System Cleaner ─────────────────────────────────────────────────────────────

def _dir_size_mb(path):
    """Best-effort recursive directory size in MB.

    Uses `du` on Linux/macOS (fast, single kernel call) and falls back to
    os.walk capped at 100 000 files to avoid hanging on large browser caches.
    """
    import platform as _plat
    if not os.path.exists(path):
        return 0
    system = _plat.system()
    if system == "Linux":
        try:
            r = subprocess.run(["du", "-sb", path],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                parts = r.stdout.split()
                if parts:
                    return int(parts[0]) // (1024 * 1024)
        except (OSError, subprocess.TimeoutExpired, ValueError):
            pass
    elif system == "Darwin":
        try:
            r = subprocess.run(["du", "-sk", path],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                parts = r.stdout.split()
                if parts:
                    return (int(parts[0]) * 1024) // (1024 * 1024)
        except (OSError, subprocess.TimeoutExpired, ValueError):
            pass
    # Fallback (Windows or du failure) — cap at 100 000 files / 8 s to stay fast
    total = 0
    count = 0
    t0 = time.time()
    try:
        for dirpath, _, filenames in os.walk(path):
            for fn in filenames:
                count += 1
                if count > 100_000:
                    return total // (1024 * 1024)
                try:
                    total += os.path.getsize(os.path.join(dirpath, fn))
                except OSError:
                    pass
            if (time.time() - t0) > 8.0:   # guard slow / network filesystems
                break
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
            reporter.finding(
                "INFO", f"{name} browser cache: {mb} MB",
                f"{name}'s cache at {d} will be rebuilt automatically — safe to clear "
                "(close the browser first).",
                "Clear it from the browser's own settings: Settings → Privacy → Clear browsing data.",
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


