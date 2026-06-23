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


# ── remediate-from-report rejects tampered commands (2.3) ───────────────────────

class TestRemediateRevalidation:
    def test_tampered_report_command_is_not_executed(self, tmp_path, monkeypatch, capsys):
        import json
        from exposure_checker import _remediate

        # A report whose fix_cmds were edited to smuggle in an attacker command
        # alongside a legitimate one.
        report = {"timestamp": "t", "checks": [{"check": "X", "findings": [
            {"severity": "HIGH", "label": "legit", "why": "", "fix": "",
             "fix_cmds": ["echo legit-fix"]},
            {"severity": "HIGH", "label": "evil", "why": "", "fix": "",
             "fix_cmds": ["touch /tmp/PWNED_by_tampered_report"]},
        ]}]}
        rpath = tmp_path / "tampered.json"
        rpath.write_text(json.dumps(report))

        # Live scan only vouches for the legit command — the injected one is absent.
        monkeypatch.setattr(_remediate, "_live_fix_cmds", lambda: {"echo legit-fix"})

        ran = []
        monkeypatch.setattr(_remediate, "_run_fix_cmd",
                            lambda cmd: (ran.append(cmd) or (0, "")))

        # The legit fix succeeds and the injected one is skipped (not failed), so
        # the run completes without sys.exit.
        _remediate._remediate_main([str(rpath), "--all", "--yes"])

        assert "echo legit-fix" in ran
        assert "touch /tmp/PWNED_by_tampered_report" not in ran

    def test_yes_refused_when_validation_unavailable(self, tmp_path, monkeypatch):
        import json
        from exposure_checker import _remediate

        report = {"timestamp": "t", "checks": [{"check": "X", "findings": [
            {"severity": "HIGH", "label": "a", "why": "", "fix": "",
             "fix_cmds": ["echo x"]},
        ]}]}
        rpath = tmp_path / "r.json"
        rpath.write_text(json.dumps(report))

        monkeypatch.setattr(_remediate, "_live_fix_cmds", lambda: None)
        ran = []
        monkeypatch.setattr(_remediate, "_run_fix_cmd",
                            lambda cmd: (ran.append(cmd) or (0, "")))

        with pytest.raises(SystemExit):
            _remediate._remediate_main([str(rpath), "--all", "--yes"])
        assert ran == []   # nothing ran — --yes refused without validation


# ── Static guard: no raw quote-brace interpolation in executed commands ──────────
#
# This is the mechanical enforcement of the invariant. It parses every checks/*.py
# module and, *within executed-command contexts only* (_ps(...), _run(...),
# _run_fix_cmd(...), and fix_cmds=[...] / fix_cmds=[...] assignments), flags any
# f-string interpolation that sits immediately against a quote character unless the
# interpolated value is produced by a quote helper (_ps_quote / _shell_quote /
# shlex.quote). Message/description text (label/why/fix) is never scanned, so
# human-readable strings keep their natural quoting.
#
# Reintroducing the temp-executable pattern  Remove-Item -Path '{path}' ...  makes
# this test fail (demonstrated in test_guard_catches_reintroduced_vuln).

import ast
import glob

_CHECKS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                           "exposure_checker", "checks")
_RUNNER_FUNCS = {"_ps", "_run", "_run_fix_cmd"}
_QUOTERS = {"_ps_quote", "_shell_quote", "quote"}  # quote == shlex.quote / *.quote


def _is_quoter_call(node):
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    if isinstance(f, ast.Name):
        return f.id in _QUOTERS
    if isinstance(f, ast.Attribute):
        return f.attr in _QUOTERS
    return False


def _raw_quoted_interpolations(joined: ast.JoinedStr):
    """Yield FormattedValue nodes that sit against a quote char and are not a
    quote-helper call (i.e. the dangerous '{value}' / "{value}" shape)."""
    vals = joined.values
    for i, v in enumerate(vals):
        if not isinstance(v, ast.FormattedValue):
            continue
        prev = vals[i - 1] if i > 0 else None
        nxt = vals[i + 1] if i + 1 < len(vals) else None
        prev_q = (isinstance(prev, ast.Constant) and isinstance(prev.value, str)
                  and prev.value and prev.value[-1] in "'\"")
        next_q = (isinstance(nxt, ast.Constant) and isinstance(nxt.value, str)
                  and nxt.value and nxt.value[0] in "'\"")
        if (prev_q or next_q) and not _is_quoter_call(v.value):
            yield v


def _command_joinedstrs(tree: ast.AST):
    """Yield every JoinedStr that lives in an executed-command context."""
    out = []

    def collect(node):
        for sub in ast.walk(node):
            if isinstance(sub, ast.JoinedStr):
                out.append(sub)

    for node in ast.walk(tree):
        # _ps(...), _run(...), _run_fix_cmd(...)
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else (
                fn.attr if isinstance(fn, ast.Attribute) else None)
            if name in _RUNNER_FUNCS:
                for a in node.args:
                    collect(a)
            # fix_cmds=[...] keyword
            for kw in node.keywords:
                if kw.arg == "fix_cmds":
                    collect(kw.value)
        # fix_cmds = [...] / fix_cmds: list = [...]
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "fix_cmds":
                    collect(node.value)
        if isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == "fix_cmds":
                if node.value is not None:
                    collect(node.value)
    return out


def _scan_source(src: str):
    tree = ast.parse(src)
    offenders = []
    for joined in _command_joinedstrs(tree):
        for fv in _raw_quoted_interpolations(joined):
            offenders.append(getattr(fv, "lineno", -1))
    return offenders


class TestNoRawQuotedInterpolations:
    def test_all_check_modules_are_clean(self):
        problems = {}
        for path in sorted(glob.glob(os.path.join(_CHECKS_DIR, "*.py"))):
            offenders = _scan_source(open(path, encoding="utf-8").read())
            if offenders:
                problems[os.path.basename(path)] = offenders
        assert not problems, (
            "Raw quote-brace interpolation in an executed command (use "
            "_ps_quote/_shell_quote/shlex.quote):\n" +
            "\n".join(f"  {f}: lines {ls}" for f, ls in problems.items()))

    def test_guard_catches_reintroduced_vuln(self):
        # The exact shape of the original temp-executable RCE must be caught.
        vuln = (
            "def f(path):\n"
            "    reporter.finding('HIGH', 'x', 'y', 'z',\n"
            "        fix_cmds=[f\"Remove-Item -Path '{path}' -Force\"])\n"
        )
        assert _scan_source(vuln), "guard failed to flag the reintroduced vuln"

        # And the fixed shape must be accepted.
        safe = (
            "def f(path):\n"
            "    reporter.finding('HIGH', 'x', 'y', 'z',\n"
            "        fix_cmds=[f\"Remove-Item -Path {_ps_quote(path)} -Force\"])\n"
        )
        assert not _scan_source(safe), "guard wrongly flagged the safe form"

    def test_guard_ignores_message_text(self):
        # A raw-quoted interpolation in description text (not an executed context)
        # must NOT be flagged.
        msg = (
            "def f(path):\n"
            "    reporter.finding('HIGH', 'x',\n"
            "        f\"'{path}' is suspicious\", 'fix text')\n"
        )
        assert not _scan_source(msg), "guard wrongly flagged message text"
