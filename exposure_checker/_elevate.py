"""Privilege detection and elevated batch-fix execution — pure, no Tkinter.

These helpers were extracted verbatim from ``gui/app.py`` so the webview UI can
run the real fix path without importing tkinter. The Tkinter app re-imports every
name from here, so its behaviour is byte-for-byte unchanged.

``_ensure_admin`` deliberately stays in ``gui/app.py``: it shows a Tk messagebox
and re-execs the Tk entry point, so it is genuinely GUI-coupled. The webview shell
provides its own admin-ensure.
"""

import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

import exposure_checker as ec

_OS = platform.system()  # "Linux" | "Darwin" | "Windows"


def _is_root():
    if _OS == "Windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def _elevation_available() -> bool:
    """True if we can ask for elevated privileges on this platform."""
    if _OS == "Linux":
        return bool(shutil.which("pkexec"))
    if _OS == "Darwin":
        return bool(shutil.which("osascript"))
    if _OS == "Windows":
        return bool(shutil.which("powershell"))
    return False


def _batch_fix_elevated(findings):
    """Collect ALL fix_cmds and run them with a SINGLE elevation prompt.
    Returns list of (cmd, returncode, output) or None if no escalation tool."""
    cmds = [cmd for f in findings for cmd in f.get("fix_cmds", [])]
    if not cmds:
        return []

    if _is_root():
        results = []
        for cmd in cmds:
            rc, out = ec._run_fix_cmd(cmd)
            results.append((cmd, rc, out))
        return results

    if _OS == "Darwin":
        return _batch_fix_macos(cmds)
    if _OS == "Windows":
        return _batch_fix_windows(cmds)
    return _batch_fix_linux(cmds)


def _batch_fix_linux(cmds):
    """Single pkexec prompt for all fixes on Linux."""
    pkexec = shutil.which("pkexec")
    if not pkexec:
        return None

    lines = ["#!/bin/bash"]
    for i, cmd in enumerate(cmds):
        lines.append(f'printf "\\n##ECCMD{i}##\\n"')
        lines.append(f'{{ {cmd}; }} 2>&1')
        lines.append(f'printf "##ECEXIT{i}:%d##\\n" "$?"')

    fd, spath = tempfile.mkstemp(suffix=".sh", prefix="ec-fix-")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        os.chmod(spath, 0o700)
        result = subprocess.run([pkexec, "bash", spath],
                                capture_output=True, text=True, timeout=120)
        return _parse_batch_output(cmds, result.stdout)
    except subprocess.TimeoutExpired:
        return [(c, 1, "timed out") for c in cmds]
    except OSError as exc:
        return [(c, 1, str(exc)) for c in cmds]
    finally:
        try:
            os.unlink(spath)
        except OSError:
            pass


def _batch_fix_macos(cmds):
    """Single osascript administrator prompt for ALL fixes on macOS.

    Previously each command spawned its own `do shell script ... with
    administrator privileges` → one password dialog *per fix*. Now all
    commands run inside one marker-tagged shell script behind one prompt.
    """
    lines = []
    for i, cmd in enumerate(cmds):
        lines.append(f'printf "\\n##ECCMD{i}##\\n"')
        lines.append(f'{{ {cmd}; }} 2>&1')
        lines.append(f'printf "##ECEXIT{i}:%d##\\n" "$?"')
    fd, spath = tempfile.mkstemp(suffix=".sh", prefix="ec-fix-")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        os.chmod(spath, 0o700)
        safe = spath.replace("\\", "\\\\").replace('"', '\\"')
        script = f'do shell script "/bin/bash \\"{safe}\\"" with administrator privileges'
        r = subprocess.run(["osascript", "-e", script],
                           capture_output=True, text=True, errors="replace",
                           timeout=max(120, 60 * len(cmds)))
        if r.returncode != 0 and "##ECCMD" not in r.stdout:
            # User cancelled the auth dialog or osascript failed outright
            msg = r.stderr.strip() or "authorization cancelled"
            return [(c, 1, msg) for c in cmds]
        return _parse_batch_output(cmds, r.stdout)
    except subprocess.TimeoutExpired:
        return [(c, 1, "timed out") for c in cmds]
    except OSError as exc:
        return [(c, 1, str(exc)) for c in cmds]
    finally:
        try:
            os.unlink(spath)
        except OSError:
            pass


def _batch_fix_windows(cmds):
    """Single UAC prompt for ALL fixes on Windows.

    Each command is wrapped in try/catch with $ErrorActionPreference='Stop'
    so cmdlet failures are caught. Output is written via Out-File -Encoding
    ASCII to guarantee no BOM — PS5.1 Add-Content -Encoding UTF8 writes a
    BOM on new files which breaks marker parsing.
    """
    no_window = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    fd, script_path = tempfile.mkstemp(suffix=".ps1", prefix="ec-fix-")
    out_path = script_path + ".out"
    # Both paths come from tempfile.mkstemp() so they can't contain quotes, but
    # quote anyway so the escaping invariant has no exceptions. ps_out fills a
    # simple '{}' slot (ec._ps_quote wraps + escapes); ps_scr is embedded inside
    # a nested \"...\" Start-Process argument below, so it keeps an inline escape.
    ps_scr = script_path.replace("'", "''")  # PS single-quote escape (nested)

    lines = [f"$__f = {ec._ps_quote(out_path)}"]
    for i, cmd in enumerate(cmds):
        lines += [
            f'"##ECCMD{i}##" | Out-File -Append -Encoding ASCII -FilePath $__f',
            f"$__c = 0",
            f"try {{",
            f"    $ErrorActionPreference = 'Stop'",
            f"    & {{ {cmd} }} 2>&1 | Out-String -Stream"
            f" | Out-File -Append -Encoding ASCII -FilePath $__f",
            f"    if ($LASTEXITCODE) {{ $__c = $LASTEXITCODE }}",
            f"}} catch {{",
            f"    $ErrorActionPreference = 'Continue'",
            f'    "Error: $_" | Out-File -Append -Encoding ASCII -FilePath $__f',
            f"    $__c = 1",
            f"}}",
            f"$ErrorActionPreference = 'Continue'",
            f'"##ECEXIT{i}:$__c##" | Out-File -Append -Encoding ASCII -FilePath $__f',
        ]
    try:
        with os.fdopen(fd, "w", encoding="utf-8-sig") as fh:
            fh.write("\n".join(lines) + "\n")
        runner = (
            f"Start-Process powershell.exe "
            f"-ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','\"{ps_scr}\"' "
            f"-Verb RunAs -WindowStyle Hidden -Wait"
        )
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", runner],
            capture_output=True, text=True, errors="replace",
            timeout=max(120, 60 * len(cmds)), creationflags=no_window,
        )
        if "denied" in (r.stderr or "").lower() or "cancel" in (r.stderr or "").lower():
            return [(c, 1, "UAC prompt declined") for c in cmds]
        try:
            with open(out_path, encoding="ascii", errors="replace") as fh:
                stdout = fh.read()
        except OSError:
            stdout = ""
        if "##ECCMD" not in stdout:
            return [(c, 1, (r.stderr or "elevation failed").strip()) for c in cmds]
        return _parse_batch_output(cmds, stdout)
    except subprocess.TimeoutExpired:
        return [(c, 1, "timed out") for c in cmds]
    except OSError as exc:
        return [(c, 1, str(exc)) for c in cmds]
    finally:
        for p in (script_path, out_path):
            try:
                os.unlink(p)
            except OSError:
                pass


def _parse_batch_output(cmds, stdout):
    """Parse marker-tagged output from the batch-fix script."""
    outputs: dict = {}
    exits:   dict = {}
    cur_idx        = None
    cur_out:  list = []

    for line in stdout.splitlines():
        m = re.match(r"##ECCMD(\d+)##", line.strip())
        if m:
            if cur_idx is not None:
                outputs[cur_idx] = "\n".join(cur_out).strip()
            cur_idx = int(m.group(1))
            cur_out = []
            continue
        m = re.match(r"##ECEXIT(\d+):(\d+)##", line.strip())
        if m:
            i, rc = int(m.group(1)), int(m.group(2))
            exits[i] = rc
            if cur_idx is not None:
                outputs[cur_idx] = "\n".join(cur_out).strip()
                cur_idx = None
                cur_out = []
            continue
        if cur_idx is not None:
            cur_out.append(line)

    return [(cmd, exits.get(i, 1), outputs.get(i, ""))
            for i, cmd in enumerate(cmds)]


def _assemble_preview_cmds(findings, force_sudo=None) -> str:
    """The commands that will run, one per line — sudo-prefixed on POSIX when
    elevation applies. Shared by the confirm dialog and the denied dialog so the
    preview always matches what is actually executed."""
    all_cmds = [cmd for f in findings for cmd in f.get("fix_cmds", [])]
    if _OS == "Windows":
        return "\n".join(all_cmds)
    use_sudo = (not _is_root()) if force_sudo is None else force_sudo
    if use_sudo:
        return "\n".join(f"sudo {c}" for c in all_cmds)
    return "\n".join(all_cmds)
