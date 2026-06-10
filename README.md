# Exposure Checker

A self-hosted security scanner for machines you own. Detects risky open ports,
weak configurations, brute-force attempts, outdated packages, malware indicators,
and more — then tells you exactly how to fix each finding.

Runs on **Linux, macOS, and Windows**. No cloud, no telemetry — everything stays on your machine.

> **Only scan systems you own or have written permission to test.**

---

## Download

Pre-built desktop app — no Python required:

| Platform | Download |
|---|---|
| macOS | `exposure-checker-macos.dmg` — open DMG → drag to Applications |
| Windows | `Exposure Checker.exe` — run as Administrator for full results |
| Linux | `exposure-checker-linux` — `chmod +x` then run |

Go to the [Releases page](../../releases/latest) to download.

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
| Malware scan | `--check-malware` | ClamAV + temp executables + suspicious procs + ld.so.preload + script patterns | ClamAV | Windows Defender + registry Run keys + temp executables + suspicious procs |
| TLS certificate | `--tls-check HOST` | ✓ | ✓ | ✓ |
| Container CVEs | `--trivy-scan` | Trivy (if installed) | Trivy (if installed) | Trivy (if installed) |

Run everything at once:

```bash
exposure-checker --full-audit
```

---

## Output formats

```bash
# Human-readable (default)
exposure-checker --full-audit

# Self-contained HTML report — risk score, severity charts, fix commands
exposure-checker --full-audit --output report.html

# Machine-readable JSON
exposure-checker --full-audit --output report.json

# Exit 1 if any HIGH or CRITICAL finding (useful in CI)
exposure-checker --full-audit --fail-on high
```

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

## Remediation

Every finding ships with a specific fix command. Run them automatically:

```bash
# Interactive — review and approve each fix
exposure-checker remediate report.json

# Apply everything at once
exposure-checker remediate report.json --all --yes

# Dry run — show what would be executed
exposure-checker remediate report.json --dry-run
```

---

## Baseline and diff

Track what changes between scans:

```bash
# Save current state as baseline
exposure-checker --full-audit --save-baseline

# Later — show only what changed
exposure-checker --full-audit --diff-baseline

# Compare two saved reports
exposure-checker diff before.json after.json

# Exit 1 in CI if any new HIGH+ findings appear
exposure-checker --full-audit --diff-baseline --fail-on high
```

---

## Scheduled scans

Install a recurring scan with optional email notification:

```bash
exposure-checker schedule install --email you@example.com
exposure-checker schedule status
exposure-checker schedule remove
```

Uses cron (Linux/macOS) or Task Scheduler (Windows).
SMTP credentials go in `~/.config/exposure-checker/config.ini` (chmod 600, never committed).

---

## Desktop UI

```bash
exposure-checker-ui
```

Dark-theme desktop app with:

- Animated risk score ring and letter grade
- Real-time findings table with severity filtering
- **System cleaner** — scans for reclaimable disk space (APT cache, old kernels, journal bloat, Windows temp/WU cache, crash dumps, Recycle Bin)
- **Malware / antivirus tab** — ClamAV signatures + heuristic indicators (Linux/macOS) or Windows Defender + registry persistence + suspicious processes
- One-click remediation with per-command confirmation
- HTML and PDF report export
- Scan history with score trend chart
- Accepted risks — suppress known-safe findings
- Snapshot and restore — capture and revert system config state
- Compliance profiles — CIS Level 1, HIPAA Basics, PCI-DSS Lite
- Scheduled scans with desktop notifications

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
