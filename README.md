# Exposure Checker

A self-hosted **security, antivirus, and cleanup** tool for machines you own.
No cloud, no telemetry, no accounts — everything stays on your machine.

- **Protect** — finds risky open ports, weak configs, brute-force attempts, outdated packages,
  and malware indicators, then drives your OS's *own* defenses (Windows Defender /
  macOS XProtect + Gatekeeper / ClamAV; Windows Firewall / pf / macOS application firewall)
  and tells you exactly how to fix each finding.
- **Clean** — reclaims disk space CCleaner-style: browser and package-manager caches,
  system temp/log bloat, old kernels, crash dumps, Xcode/iOS debris, Recycle Bin,
  and a **startup-programs audit** (the biggest lever for "my machine got slower").
- **Track** — risk score and letter grade, history trend, baselines, diffs,
  scheduled scans, and HTML/PDF reports.

Runs on **Linux, macOS, and Windows**.

---

## Download

Pre-built desktop app — **no Python, no terminal required:**

| Platform | File | Steps |
|---|---|---|
| **Windows** | `Exposure Checker.exe` | Right-click → **Run as administrator** |
| **macOS** | `exposure-checker-macos.dmg` | Open DMG → drag to Applications → right-click → Open |
| **Linux** | `exposure-checker-linux` | `chmod +x exposure-checker-linux && sudo ./exposure-checker-linux` |

→ **[Download the latest release](../../releases/latest)**

> The app requires administrator / root access so it can read system logs,
> firewall state, and kernel parameters. It will prompt you for this on launch.

---

## Quick start

1. **Download and launch** the app for your platform (see above).
2. On first launch a **Welcome dialog** appears — choose **Quick Scan** (security only,
   ~30 s) or **Full Audit** (security + antivirus + cleaner).
3. The scan runs automatically. When it finishes:
   - The **risk score and letter grade** (A–F) appear on the left.
   - If anything critical is found, a **red alert card** pins to the top of the findings
     list with a one-click **Fix it →** button.
   - The **"Last scan"** badge in the status bar updates so you always know when
     you last checked.
4. Hit **Fix all issues** to apply every available fix in a single elevation prompt —
   one UAC dialog on Windows, one password prompt on macOS/Linux.

---

## Risk score

Every scan produces a score out of 100 and a letter grade:

| Grade | Score | Meaning |
|---|---|---|
| A | 90–100 | Excellent posture |
| B | 75–89 | Minor issues to address |
| C | 50–74 | Needs attention |
| D | 25–49 | Significant exposure |
| F | 0–24 | Critical risk |

---

## Desktop UI features

- Venice canal flythrough splash + animated seagull mascot throughout
- Animated radar/score ring with grade, plus scan-history trend sparkline
- Real-time findings cards with severity filtering and **one-click remediation**
  (single elevation prompt per batch — one UAC dialog on Windows, one password dialog on macOS)
- **Three scan tabs:** Security · Antivirus · Cleaner
- HTML and PDF report export
- Accepted risks — suppress known-safe findings permanently
- Snapshot and restore — capture and revert system config state
- Compliance profiles — CIS Level 1, HIPAA Basics, PCI-DSS Lite
- Scheduled scans with desktop notifications

---

## Command-line interface

Install from source first (see below), then:

```bash
# Full audit — all local checks
sudo exposure-checker --full-audit

# Specific checks
sudo exposure-checker --ssh-audit --check-firewall --check-packages

# Compliance profiles — auto-enables required checks, exits 1 on failure
sudo exposure-checker --profile cis-l1
sudo exposure-checker --profile hipaa
sudo exposure-checker --profile pci-dss

# Save a report
sudo exposure-checker --full-audit --output report.html   # self-contained HTML
sudo exposure-checker --full-audit --output report.json   # machine-readable

# CI gate — exit 1 if any HIGH or CRITICAL finding
sudo exposure-checker --full-audit --fail-on high

# Baseline and drift detection
sudo exposure-checker --full-audit --save-baseline
sudo exposure-checker --full-audit --diff-baseline --fail-on high

# Apply fixes from a saved report
sudo exposure-checker remediate report.json --all --yes

# Scheduled weekly scan with email
exposure-checker schedule install --email you@example.com
```

### Compliance profiles

`--profile` auto-enables the checks required for the chosen standard and prints a per-control pass/fail table:

```
  ─── CIS Level 1 ─────────────────────────────────────────────
  ssh              PASS
  firewall         FAIL  ← Firewall disabled
  world-writable   PASS
  suid             PASS
  kernel           FAIL  ← kernel.randomize_va_space = 0
  listeners        PASS
  packages         PASS

  Compliance  5/7  [████████████░░░░░░░░]  71%  FAIL
```

Exits 0 on full compliance, 1 on any failure — composable with CI.

---

## What it checks

| Check | Flag | Linux | macOS | Windows |
|---|---|---|---|---|
| Port scan | *(always)* | ✓ | ✓ | ✓ |
| SSH audit | `--ssh-audit` | `/etc/ssh/sshd_config` | `/etc/ssh/sshd_config` | `C:\ProgramData\ssh\sshd_config` |
| Firewall | `--check-firewall` | ufw / iptables / firewalld | pf / socketfilterfw | Windows Firewall profiles |
| Listening services | `--check-listeners` | `ss` | `lsof` | PowerShell Get-NetTCPConnection |
| Auth log | `--check-auth` | `/var/log/auth.log` | `log show` | Security Event Log (ID 4625) |
| Packages | `--check-packages` | apt / dnf / yum | Homebrew + softwareupdate | winget + Windows Update |
| Kernel hardening | `--check-kernel` | 10 sysctl checks | sysctl + SIP | UAC, ASLR, DEP, BitLocker, LSA Protection, SMB signing, PS policy, Secure Boot |
| Sensitive file perms | `--check-sensitive-perms` | `/etc/shadow`, sudoers, SSH keys | SSH keys | SAM/SYSTEM hives, Unattend.xml |
| SUID/SGID binaries | `--check-suid` | ✓ | — | — |
| World-writable files | `--check-world-writable` | 7 system dirs | 7 system dirs | System32, SysWOW64, Program Files |
| Cron / scheduled tasks | `--check-cron` | crontab | crontab | Task Scheduler |
| User accounts | `--check-user-accounts` | Extra UID-0, empty passwords | Extra UID-0 | Get-LocalUser, no-password accounts |
| Docker socket | `--check-docker` | POSIX mode bits | POSIX mode bits | Named pipe ACL |
| Malware / antivirus | `--check-malware` | ClamAV + temp executables + suspicious procs + ld.so.preload + script patterns | Gatekeeper + XProtect freshness + launchd persistence + Mach-O temp binaries + ClamAV (if installed) | Defender (third-party-AV aware) + active-threat check + registry Run keys + temp executables + suspicious procs |
| Startup programs | `--check-startup` | `~/.config/autostart` | LaunchAgents / LaunchDaemons + Login Items | Run keys (HKLM/HKCU) + Startup folders |
| System cleaner | `--check-cleaner` | APT/DNF cache, orphans, old kernels, journal, crash dumps, temp, thumbnails, browser/dev caches | user caches, Trash, logs, Xcode DerivedData, iOS backups, brew cleanup, temp, browser/dev caches | temp, Windows Update cache, Delivery Optimization, Recycle Bin, crash dumps, browser/dev caches |
| TLS certificate | `--tls-check HOST` | ✓ | ✓ | ✓ |
| Container CVEs | `--trivy-scan` | Trivy (if installed) | Trivy (if installed) | Trivy (if installed) |

---

## Install from source

**Linux / macOS** (Python 3.9+ required):

```bash
git clone https://github.com/ikerscode/exposure-checker
cd exposure-checker
bash install.sh
```

**Windows** (Python 3.9+ required — [python.org](https://www.python.org/downloads/)):

```powershell
# In an elevated (Administrator) PowerShell
git clone https://github.com/ikerscode/exposure-checker
cd exposure-checker
Set-ExecutionPolicy Bypass -Scope Process -Force
.\install.ps1
```

One pip dependency: `cryptography` (TLS checks only). Everything else is Python stdlib.

---

## GitHub Actions

**Weekly security scan** (self-hosted runner on your own machine):

`.github/workflows/security-scan.yml` — runs `--full-audit --diff-baseline`, uploads
the report as a workflow artifact, exits 1 on new HIGH findings.

**Build desktop app** (GitHub-hosted runners, all three platforms):

Push a version tag to trigger a full build and publish a GitHub Release:

```bash
git tag v1.0.1
git push origin v1.0.1
```

CI builds `exposure-checker-macos.dmg`, `Exposure Checker.exe`, and `exposure-checker-linux`
and attaches them to the release automatically.

---

## Security notes

- Pure Python stdlib for the scan engine — no supply-chain attack surface beyond `cryptography`.
- No hardcoded secrets. SMTP credentials live in a gitignored config file.
- All subprocess calls use argument lists, never shell string concatenation.
- Validates scan targets before connecting; defaults to `127.0.0.1`.
- Scan reports are gitignored — they reveal your weak spots.
- Requires administrator/root: the app will prompt you on launch and exit if access is denied.
