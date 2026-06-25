"""Performance checks: startup, power, GPU, protection hardening, network perf, memory tuning, system resources."""

import datetime
import json
import os
import re
import shlex
import shutil
import math
import socket
import ssl
import time
import subprocess
import sys

from .._core import (
    _OS, _ps, _ps_quote, _shell_quote, _truncate,
    RISKY_PORTS, SPECIAL, SEVERITY_ORDER,
    _CRYPTO_OK, _cx509,
    _NO_WINDOW,
)

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
                    fix_cmds=[cmd], revertable=False,
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
            "Gullwing", "DisabledStartup",
        )
        if env == "PROGRAMDATA":
            dest_root = os.path.join(base, "Gullwing", "DisabledStartup")
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
                fix_cmds=[cmd], revertable=False,
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
                fix_cmds=[cmd], revertable=False,
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
                                "Gullwing", "Disabled LaunchItems")
    else:
        dest_dir = "/Library/Application Support/Gullwing/Disabled LaunchItems"
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
                fix_cmds=[_mac_disable_launch_item_cmd(path, scope)], revertable=False,
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
                    fix_cmds=[f"osascript -e {_shell_quote(script)}"], revertable=False,
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
                fix_cmds=[cmd], revertable=False,
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
                fix_cmds=["powercfg /setactive SCHEME_MIN"], revertable=False,
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
            ], revertable=False,
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
            ], revertable=False,
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
            ], revertable=False,
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
            ], revertable=False,
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
            ], revertable=False,
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
            ], revertable=False,
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
            fix_cmds=["pmset -a lowpowermode 0"], revertable=False,
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
                    fix_cmds=["powerprofilesctl set performance"], revertable=False,
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
                ], revertable=False,
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
            ], revertable=False,
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
            ], revertable=False,
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
            ], revertable=False,
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
            ], revertable=False,
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
            ], revertable=False,
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
            ], revertable=False,
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
            ], revertable=False,
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

    # ── MSI (Message Signalled Interrupts) mode for GPU/NIC ──────────────────
    # Moved to overclock.py (_oc_msi_mode_windows) so it appears alongside
    # the full OC advisory rather than buried in GPU settings.

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
            fix_cmds=["pmset -a gpuswitch 1"], revertable=False,
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
                        fix_cmds=["nvidia-smi -pm 1"], revertable=False,
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
                    fix_cmds=[f"echo auto > {_shell_quote(path)}"], revertable=False,
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
                    fix_cmds=[f"echo performance > {_shell_quote(pp_path)}"], revertable=False,
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
                fix_cmds=["Set-MpPreference -EnableControlledFolderAccess Enabled"], revertable=False,
            )
            n += 1
        if _mp_value_disabled(prefs.get("PUAProtection", 0)):
            reporter.finding(
                "MEDIUM", "Potentially unwanted app protection is off",
                "PUA protection blocks common bundleware, miners, and browser hijackers.",
                "Enable Microsoft Defender PUA protection.",
                fix_cmds=["Set-MpPreference -PUAProtection Enabled"], revertable=False,
            )
            n += 1
        if _mp_value_disabled(prefs.get("EnableNetworkProtection", 0)):
            reporter.finding(
                "REVIEW", "Defender network protection is off",
                "Network protection can block known malicious domains and outbound callbacks.",
                "Enable Defender network protection if it is supported on this edition.",
                fix_cmds=["Set-MpPreference -EnableNetworkProtection Enabled"], revertable=False,
            )
            n += 1
        if prefs.get("DisableScriptScanning") is True:
            reporter.finding(
                "HIGH", "Defender script scanning is disabled",
                "Script scanning catches PowerShell, JavaScript, and VBScript malware before execution.",
                "Re-enable script scanning.",
                fix_cmds=["Set-MpPreference -DisableScriptScanning $false"], revertable=False,
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
            fix_cmds=["Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"], revertable=False,
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
            ], revertable=False,
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
            ], revertable=False,
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
            ], revertable=False,
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
            ], revertable=False,
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
            ], revertable=False,
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
            fix_cmds=["Set-MpPreference -DisableRealtimeMonitoring $false"], revertable=False,
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
            fix_cmds=["Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue"], revertable=False,
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
            ], revertable=False,
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
                fix_cmds=[f"{_shell_quote(sff)} --setstealthmode on"], revertable=False,
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
            ], revertable=False,
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
                    fix_cmds=[fix_cmd], revertable=False,
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
                fix_cmds=["spctl --master-enable"], revertable=False,
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
                ], revertable=False,
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
                fix_cmds=[f"{_shell_quote(sff)} --setglobalstate on"], revertable=False,
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
                    fix_cmds=["setenforce 1"], revertable=False,
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
                ], revertable=False,
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
                    fix_cmds=["systemctl enable --now dnf-automatic.timer"], revertable=False,
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
                    fix_cmds=["systemctl enable --now fail2ban"], revertable=False,
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
                    fix_cmds=["systemctl enable --now auditd"], revertable=False,
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
                ], revertable=False,
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
                fix_cmds=["Enable-NetAdapterRss -Name * -ErrorAction SilentlyContinue"], revertable=False,
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
                ], revertable=False,
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
            ], revertable=False,
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
                ], revertable=False,
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
                    fix_cmds=["systemctl enable --now irqbalance"], revertable=False,
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
            ], revertable=False,
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
            ], revertable=False,
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
            ], revertable=False,
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
            ], revertable=False,
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
            ], revertable=False,
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
            ], revertable=False,
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
            ], revertable=False,
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
                ], revertable=False,
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
                fix_cmds=["sysctl -w vm.swappiness=10"], revertable=False,
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
                ], revertable=False,
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
                          "sysctl -w vm.dirty_background_ratio=3"], revertable=False,
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
                        f"echo mq-deadline > /sys/block/{_shell_quote(dev)}/queue/scheduler"
                    ], revertable=False,
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
                    ], revertable=False,
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
                ], revertable=False,
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
                ], revertable=False,
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
                fix_cmds=["tmutil stopbackup"], revertable=False,
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
            out, rc = _ps(
                "(Get-NetAdapter | Where-Object {"
                " $_.InterfaceDescription -match 'VPN|Tunnel|WireGuard|OpenVPN|Nord|Express|Proton'"
                " -or $_.Name -match 'VPN|Tunnel|WireGuard|tun|tap'"
                " } | Where-Object { $_.Status -eq 'Up' } | Measure-Object).Count"
            )
            vpn_up = rc == 0 and out.strip() not in ("", "0")
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
            out, rc = _ps(
                "Get-PSDrive -PSProvider FileSystem | Where-Object {"
                " $_.Used -and ($_.Used / ($_.Used + $_.Free)) -gt 0.90"
                " } | ForEach-Object {"
                " $pct = [int]($_.Used / ($_.Used + $_.Free) * 100);"
                " \"$($_.Root) $pct%\""
                " }"
            )
            drives = [ln.strip() for ln in out.splitlines() if ln.strip()] if rc == 0 else []
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
            out, rc = _ps(
                "Get-Process | Where-Object { $_.CPU -and $_.Name -notmatch "
                "'Idle|System|Registry|svchost|csrss|lsass|winlogon|smss|wininit|fontdrvhost' }"
                " | Sort-Object CPU -Descending | Select-Object -First 5"
                " | ForEach-Object { \"$($_.Name) [$([int]($_.CPU))s CPU]\" }"
            )
            hogs = [ln.strip() for ln in out.splitlines() if ln.strip()] if rc == 0 else []
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
                    with open(cp) as fh:
                        cur = int(fh.read().strip())
                    with open(mp) as fh:
                        mx = int(fh.read().strip())
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


