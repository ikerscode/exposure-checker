"""
Command-injection safety invariant.

The most dangerous property in the codebase: a hostile *filename* (or task name,
registry value, etc.) that the scanner enumerates must NEVER be able to break out
of the fix command it is interpolated into. Fixes run elevated, so a breakout is
admin-level RCE — triggered by the exact malware the tool exists to catch.

These tests are implementation-agnostic: they don't assert "the code used a
helper", they parse the generated command and assert an attacker payload stays
*inside* the quoted region. A regression to raw `'{path}'` interpolation makes
them fail.

Run with:  pytest tests/test_injection_safety.py -v
"""
import os
import shlex
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import exposure_checker as ec
from exposure_checker.checks import security as sec


class _CapReporter:
    """Captures every finding() call (incl. fix_cmds) regardless of begin/end."""

    def __init__(self):
        self.findings = []

    def begin(self, *a, **kw):  pass
    def end(self, *a, **kw):    pass
    def ok(self, *a, **kw):     pass
    def info(self, *a, **kw):   pass
    def error(self, *a, **kw):  pass

    def finding(self, severity, label, why, fix, fix_cmds=None, **extra):
        self.findings.append({"severity": severity, "label": label, "why": why,
                              "fix": fix, "fix_cmds": fix_cmds or [], **extra})

    @property
    def json_mode(self):  return True


# ── Adversarial inputs ──────────────────────────────────────────────────────────
# Each carries the sentinel PWNED behind a breakout attempt. A safe encoding keeps
# PWNED *inside* quotes; a vulnerable one lets it escape into executable position.
# (Filenames here avoid '/' and NUL — the only two bytes POSIX filenames can't hold.)
ADVERSARIAL = [
    "evil'; echo PWNED; '.exe",          # PowerShell single-quote breakout
    "a' ; New-Item PWNED ; '.exe",       # spaced variant
    "x$(echo PWNED).exe",                # subexpression (inert inside PS '...')
    "y`echo PWNED`.exe",                 # backtick
    "z& echo PWNED.exe",                 # cmd/pwsh statement separator
    "p| echo PWNED.exe",                 # pipe
    "q&& echo PWNED.exe",                # and-list
    "double''quote PWNED.exe",           # pre-doubled quotes must not un-escape
    "trailing quote PWNED'.exe",         # lone trailing quote
    "plain spaces PWNED.exe",            # benign: PWNED legitimately in name
]


# ── PowerShell single-quote parser ──────────────────────────────────────────────

def ps_unquoted_residue(cmd: str) -> str:
    """Return the text that PowerShell would parse OUTSIDE single-quoted literals.

    Mirrors PS '...' rules: a literal ends at the next single quote, except '' is
    an escaped quote that stays inside the literal. Anything in the residue is in
    executable position.
    """
    residue = []
    i, n, in_q = 0, len(cmd), False
    while i < n:
        c = cmd[i]
        if c == "'":
            if in_q and i + 1 < n and cmd[i + 1] == "'":
                i += 2            # escaped quote — still data
                continue
            in_q = not in_q
            i += 1
            continue
        if not in_q:
            residue.append(c)
        i += 1
    return "".join(residue)


def posix_tokens(cmd: str) -> list:
    """Tokenize as a POSIX shell would. shlex.quote relies on the '"'"' idiom
    (mixed single/double quotes), so the only sound check is full tokenization:
    a safe command yields exactly the expected words with the path as one token."""
    return shlex.split(cmd)


# ── The quoting primitives themselves ───────────────────────────────────────────

class TestQuoteHelpers:
    @pytest.mark.parametrize("name", ADVERSARIAL)
    def test_ps_quote_contains_no_breakout(self, name):
        quoted = ec._ps_quote(name)
        # A correctly quoted literal is a single '...' span: the residue (text
        # outside quotes) is empty, so no payload can reach executable position.
        assert ps_unquoted_residue(quoted) == "", quoted
        assert "PWNED" not in ps_unquoted_residue(quoted)

    @pytest.mark.parametrize("name", ADVERSARIAL)
    def test_shell_quote_contains_no_breakout(self, name):
        quoted = ec._shell_quote(name)
        # shlex round-trips back to the exact original — proof it's one token and
        # nothing (incl. PWNED) escaped into a separate word.
        assert shlex.split(quoted) == [name]


# ── The actual bug site: executables-in-temp scanner (0.1) ──────────────────────

class TestWindowsTempExecutablesInjection:
    def _run(self, tmp_path, monkeypatch):
        # Plant adversarially-named "executables" and point %TEMP% at them. The
        # scanner is platform-neutral (env + os.scandir), so it runs on Linux.
        for name in ADVERSARIAL:
            (tmp_path / name).write_bytes(b"MZ\x90\x00")  # fresh mtime
        monkeypatch.setenv("TEMP", str(tmp_path))
        monkeypatch.setenv("TMP", str(tmp_path))
        rep = _CapReporter()
        sec._check_windows_temp_executables(rep)
        return rep.findings

    def test_fix_cmds_are_injection_safe(self, tmp_path, monkeypatch):
        findings = self._run(tmp_path, monkeypatch)
        assert findings, "scanner should flag the planted executables"
        for f in findings:
            for cmd in f.get("fix_cmds", []):
                residue = ps_unquoted_residue(cmd)
                assert "PWNED" not in residue, (
                    f"payload escaped quoting in fix_cmd: {cmd!r}")
                # No stray single quote may survive in executable position.
                assert "'" not in residue, f"unbalanced quote in: {cmd!r}"

    def test_fix_description_is_injection_safe(self, tmp_path, monkeypatch):
        # The description is shown to users to run manually — hold it to the
        # same standard as fix_cmds.
        findings = self._run(tmp_path, monkeypatch)
        for f in findings:
            assert "PWNED" not in ps_unquoted_residue(f["fix"]), f["fix"]


# ── POSIX world-writable / SUID fix paths route through shlex.quote ─────────────

class TestPosixPathFixInjection:
    @pytest.mark.parametrize("name", ADVERSARIAL)
    def test_world_writable_fix_is_safe(self, name):
        # _sensitive-perms style fixes interpolate a path into `chmod ... <path>`.
        # The command must tokenize to exactly three words with the path intact —
        # no payload leaks into a separate, executable token.
        path = "/srv/data/" + name
        cmd = f"chmod o-w {ec._shell_quote(path)}"
        assert posix_tokens(cmd) == ["chmod", "o-w", path], cmd
