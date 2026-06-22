# Gullwing v1.1.3

**Tune it. Lock it. Send it.** — a fully local, offline desktop companion for Windows, macOS, and Linux.  
No cloud. No APIs. No telemetry. No account. Everything runs on your machine.

---

## Why Gullwing

Most "PC optimizers" do one thing, phone home, and ask you to trust a black box. Gullwing is the opposite:

- **🛡️ All-in-one.** Security audit, malware heuristics, performance tuning, disk cleaner, benchmark, and an overclock advisory — one app, six jobs, three operating systems.
- **🔒 100% local & private.** Nothing ever leaves your machine. No telemetry, no analytics, no API keys, no account. Every fix is a plain shell / PowerShell / registry command, shown to you before it runs.
- **↩️ Reversible by default.** Before changing a config file, Gullwing snapshots it to disk so one **Revert Session** button can roll the change back — and that snapshot survives even an abrupt crash. Actions that genuinely can't be undone (cleaner deletions, Windows registry/service tweaks) are labelled honestly so you always know what's reversible.
- **👁️ Transparent.** Every finding has a severity, a plain-English explanation, and the exact command behind its **Fix** button. *Copy Commands* lets you run them yourself.
- **✨ Beautiful.** A cinematic, hardware-accelerated loading screen and an Opera-GX-style live hardware monitor — a tool you actually want to open.

> **The trust pitch:** other cleaners had to earn back trust after telemetry scandals. Gullwing can't leak what it never collects.

---

## Quick Start

> **New here?** [GETTING-STARTED.md](GETTING-STARTED.md) is a two-minute first-run guide — scanning, what the score means, how Fix prompts you, and exactly what Revert can and can't undo.

> **Optional — cinematic splash:** Gullwing ships a hardware-accelerated Venice-sunset loading screen. To enable it, install the extra:
> ```bash
> pip install "pygame-ce" "numpy"      # or: pip install -e ".[splash]"
> ```
> Without these it falls back to the built-in animated splash — the app works either way.


**Recommended (all platforms):** run the installer once, then launch from your
app menu or with the `gullwing-ui` command.

### Windows
```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```
Then run `gullwing-ui`, or launch from the Start menu.

### macOS
```bash
bash scripts/install.sh
```
Then run `gullwing-ui`, or launch Gullwing from Spotlight.

### Linux
1. Install Tkinter if you haven't already:
   ```bash
   sudo apt install python3-tk -y
   ```
2. Run the installer, then search **Gullwing** in your app launcher:
   ```bash
   bash scripts/install.sh
   ```

> **Run without installing** (from the repo root, using the venv):
> ```bash
> python -m exposure_checker.gui.app
> ```

---

## What It Does

Gullwing scans your machine for security vulnerabilities and performance bottlenecks, then offers one-click fixes. Every finding shows its severity, a plain-English explanation, and a **Fix** button where a fix is available.

| Severity | Meaning |
|---|---|
| CRITICAL | Immediate risk — fix now |
| HIGH | Serious issue |
| MEDIUM | Should be addressed |
| REVIEW | Investigate and decide |
| INFO | Informational — no auto-fix |

> **Your score reflects what you can actually fix.** Findings with no one-click fix available (e.g. "enable Secure Boot in BIOS", informational notes) never count against your overall score — so applying the fixes Gullwing offers is always enough to reach a top grade.

---

## Performance Tab

Everything that affects frame rate, input latency, and system responsiveness.

### Startup & Boot

| Check | Platforms | What it fixes |
|---|---|---|
| Slow-boot startup programs | Win / macOS / Linux | Lists processes that add to login time; can disable them |
| Orphaned packages | Linux | Removes unused apt/dnf packages |
| Windows Fast Startup | Windows | Disables hibernate-on-shutdown that leaves GPU driver state stale |

### Power Settings

| Check | Platforms | What it fixes |
|---|---|---|
| Power plan not set to High Performance | Windows | Switches to High Performance / Ultimate Performance plan |
| USB Selective Suspend enabled | Windows | Disables USB power-down that causes input device wake hiccups |
| PCIe Link State Power Management active | Windows | Turns off PCIe ASPM that causes GPU/NVMe wake latency |
| CPU Core Parking below 100% | Windows | Unparks all cores so no ramp-up delay when game needs threads |
| Timer resolution at default 15.6 ms | Windows | Forces high-resolution 0.5 ms timer via bcdedit |
| Win32PrioritySeparation not tuned | Windows | Sets 0x26 for maximum foreground CPU quantum for games |
| Low Power Mode enabled | macOS | Warns that it throttles CPU/GPU |
| CPU governor not set to performance | Linux | Sets scaling governor to `performance` on all cores |

### GPU & Display

| Check | Platforms | What it fixes |
|---|---|---|
| Microsoft Basic Display Adapter active | Windows | Alerts — real GPU driver not installed |
| Hardware-Accelerated GPU Scheduling (HAGS) off | Windows | Enables HAGS for reduced GPU latency on DX12/Vulkan |
| Windows Game Mode disabled | Windows | Enables Game Mode to prioritise game CPU/GPU access |
| Background game capture (Game DVR) on | Windows | Disables background video capture that eats GPU encoder budget |
| Variable Refresh Rate (G-Sync/FreeSync) not enabled | Windows | Reminds to enable VRR in NVIDIA/AMD control panel |
| Full-screen optimisations globally disabled | Windows | Info — FSO helps some titles, hurts others |
| Multiplane Overlay (MPO) not disabled | Windows | Disables MPO — known cause of stutters on multi-monitor setups |
| Enhance Pointer Precision (mouse acceleration) on | Windows | Turns off acceleration for consistent raw mouse input |
| Resizable BAR / Smart Access Memory off | Windows | Reminds to enable ReBAR in BIOS (5–15% FPS uplift) |
| NVIDIA Low Latency Mode not set to Ultra | Windows | Info — set to Ultra in NVIDIA Control Panel |
| AMD GPU pinned to low power state | Linux | Sets AMDGPU DPM to auto/high performance |
| Vulkan ICD not installed | Linux | Warns to install `vulkan-icd-loader` / mesa-vulkan |
| Monitor not at maximum refresh rate | Windows | Shows current vs max Hz; directs to Display Settings |
| Monitor running at 60 Hz or below | Windows | Informational nudge to consider a higher-refresh display |

### Network Performance

| Check | Platforms | What it fixes |
|---|---|---|
| Nagle's algorithm active on NICs | Windows | Disables TcpAckFrequency/TCPNoDelay for lower game latency |
| Receive Side Scaling (RSS) disabled | Windows | Enables RSS to spread NIC interrupts across cores |
| NIC Energy Efficient Ethernet (EEE) on | Windows | Disables EEE that causes wake-up latency spikes |
| Windows network throttling active | Windows | Sets NetworkThrottlingIndex to 0xFFFFFFFF (disabled) |
| irqbalance not running | Linux | Installs/starts irqbalance for better interrupt distribution |
| TCP receive buffer too small | Linux | Increases `net.core.rmem_max` for throughput |
| TCP delayed ACK active | macOS | Info — delayed ACK adds ~40 ms to small packet round-trips |

### Memory & System Tuning

| Check | Platforms | What it fixes |
|---|---|---|
| SystemResponsiveness not at 0 | Windows | Sets to 0 — gives game maximum CPU slice |
| Games multimedia profile GPU Priority below 8 | Windows | Sets GPU Priority=8, Scheduling Category=High |
| Window animations enabled | Windows | Disables MinAnimate for slightly less compositor overhead |
| No active page file | Windows | Warns — missing page file can crash some games/launchers |
| SysMain (Superfetch) running | Windows | Stops and disables it — competes for disk I/O during gaming |
| Windows Search Indexer running | Windows | Info — can be disabled if you don't use Windows Search |
| Delivery Optimisation seeding to internet/LAN | Windows | Restricts upload to local network only |
| RAM not running at rated XMP/EXPO speed | Windows | Detects under-clocked RAM; directs to BIOS XMP/EXPO setting |
| Visual Effects not set to Best Performance | Windows | Sets VisualFXSetting=2, restarts Explorer |
| Steam library has no Defender exclusion | Windows | Adds Steam/steamapps to Defender exclusion list |
| Swappiness too high (default 60) | Linux | Sets `vm.swappiness=10` to keep games in RAM |
| Transparent Huge Pages set to always | Linux | Sets THP to `madvise` — avoids latency spikes |
| dirty_ratio not tuned | Linux | Reduces kernel write-back threshold for smoother I/O |
| Feral GameMode not installed | Linux | Info — install `gamemode` for per-game CPU/GPU optimisations |
| I/O scheduler not set to mq-deadline/none | Linux | Sets optimal scheduler for SSD/NVMe drives |
| CPU minimum frequency below maximum | Linux | Info — boost ramp may add microseconds on first frame |
| MangoHud not installed | Linux | Info — install for in-game performance overlay |
| Huge pages not pre-allocated | Linux | Info — pre-allocating huge pages helps some emulators |
| Spectre/Meltdown mitigations active | Linux | Info only — shows performance cost, never auto-disables |
| macOS transparency effects active | macOS | Disables Reduce Transparency via defaults write |
| Spotlight indexing on system volume | macOS | Adds system volume to Spotlight Privacy exclusions |
| App Nap enabled globally | macOS | Disables App Nap for launcher/overlay processes |
| Bluetooth enabled | macOS | Info — 2.4 GHz RF can interfere with wireless peripherals |
| Time Machine backup running | macOS | Stops active backup (disk I/O contention during gaming) |
| Time Machine has no Steam exclusion | macOS | Suggests adding Steam library to exclusions |
| Do Not Disturb / Focus not active | macOS | Info — notification banners interrupt full-screen games |

### Live System Health

| Check | Platforms | What it fixes |
|---|---|---|
| VPN active | Win / macOS / Linux | Info — VPN adds 10–100 ms latency; disconnect before gaming |
| Available RAM below 3 GB | Win / macOS / Linux | Warns of imminent paging/stutter |
| Drive over 90% full | Win / macOS / Linux | Warns of fragmented writes and possible save failures |
| Background process using ≥8% CPU | Win / macOS / Linux | Lists processes actively stealing CPU time |
| CPU thermal throttling detected | Win / macOS / Linux | Alerts that CPU is running below rated speed due to heat |

---

## Security Tab

### Port Scan

| Check | Platforms | What it fixes |
|---|---|---|
| Open ports on localhost | Win / macOS / Linux | Lists every listening port with service identification |
| SSH config audit | Linux / macOS | Checks `sshd_config` for dangerous settings |
| TLS certificate expiry | All | Checks cert validity and days remaining |

### Firewall

| Check | Platforms | What it fixes |
|---|---|---|
| No active firewall | Win / macOS / Linux | Alerts — no inbound packet filtering |
| Windows Firewall disabled on all profiles | Windows | Alerts to re-enable via Windows Security |
| ufw installed but inactive | Linux | Enables ufw |
| No firewall detected | macOS | Directs to System Settings → Firewall |

### Listening Services

| Check | Platforms | What it fixes |
|---|---|---|
| Unexpected services on network interfaces | All | Lists process name, port, and protocol |

### File System

| Check | Platforms | What it fixes |
|---|---|---|
| World-writable files in sensitive paths | Linux / macOS | Lists files any user can modify |
| SUID/SGID binaries outside expected set | Linux / macOS | Lists unusual privilege-escalation candidates |
| Sensitive file permissions | All | Checks `/etc/passwd`, `/etc/shadow`, SSH keys, etc. |

### Scheduled Tasks & Cron

| Check | Platforms | What it fixes |
|---|---|---|
| Suspicious cron jobs | Linux / macOS | Lists cron entries pointing to unusual paths |
| Windows scheduled tasks from unknown publishers | Windows | Lists tasks not signed by trusted publishers |

### Auth Log Analysis

| Check | Platforms | What it fixes |
|---|---|---|
| Brute-force SSH attempts in auth logs | Linux / macOS | Counts and lists repeated failed logins |
| Failed Windows login events | Windows | Reads Event Log for repeated failures |

### Docker

| Check | Platforms | What it fixes |
|---|---|---|
| Docker socket world-writable | Linux | Critical — equivalent to giving root to anyone |
| Docker socket world-readable | Linux | Restricts socket permissions |
| Docker image CVE scan (Trivy) | Linux | Scans local images for known CVEs if Trivy is installed |

### Malware Indicators

| Check | Platforms | What it fixes |
|---|---|---|
| Windows Defender scan + heuristic indicators | Windows | Runs Defender quick scan; checks for ld.so.preload, unusual SUID |
| macOS heuristic malware indicators | macOS | Checks LaunchAgents/Daemons for suspicious entries |

---

## Cleaner Tab

Reclaim disk space safely — every target is shown with its size before you clear it, and large directory scans are time-budgeted so they never stall.

| Check | Platforms | What it reclaims |
|---|---|---|
| User & system temp folders | Win / macOS / Linux | Stale temporary files |
| Browser caches (Chrome, Edge, Brave, Firefox, Safari) | All | Rebuildable browser cache (flagged above 150 MB) |
| Developer caches (pip, npm) | All | Package-manager download caches (flagged above 200 MB) |
| APT / DNF package cache & orphans | Linux | Downloaded `.deb`/`.rpm` files and unused dependencies |
| Old kernels | Linux | Superseded `linux-image-*` packages |
| systemd journal bloat | Linux | Vacuums logs to 200 MB |
| Crash reports & dumps | Win / Linux | `/var/crash`, minidumps, app crash dumps |
| Windows Update / Delivery Optimization cache | Windows | Downloaded update files & P2P seed cache |
| Recycle Bin / Trash | Win / macOS | Deleted files still occupying disk |
| Xcode / iOS backups / Homebrew cache | macOS | Derived data, device backups, brew downloads |
| Thumbnail cache, dpkg config debris, stale temp files | Linux | Misc reclaimable debris |

---

## Protection Tab

### Windows Hardening

| Check | What it detects | Fix available |
|---|---|---|
| TPM 2.0 not activated | TPM present but not enabled in BIOS | Info only |
| Secure Boot disabled | UEFI Secure Boot off | Info — requires BIOS change |
| Memory Integrity (HVCI / Core Isolation) off | Hypervisor-protected code integrity disabled | Enables via registry + reboot |
| UAC set to never notify | User Account Control fully disabled | Re-enables UAC prompt |
| AutoRun not fully disabled | USB/disc autorun can execute code silently | Sets NoDriveTypeAutoRun=0xFF |
| Defender Real-Time Protection off | Live malware scanning disabled | Re-enables via PowerShell |
| Defender script scanning disabled | PowerShell/script malware won't be caught | Re-enables script scanning |
| SMBv1 enabled | Legacy protocol exploited by WannaCry/NotPetya | Disables SMBv1 |
| Remote Desktop enabled | RDP exposed — common brute-force target | Info — disable if not needed |
| Remote Assistance enabled | Allows unsolicited remote access | Info |
| Guest account enabled | Unauthenticated local access | Disables guest account |
| BitLocker not enabled on system drive | Drive readable if physically removed | Info — enable in Windows Security |
| Exploit Protection Force ASLR off | Memory layout not randomised | Enables Force ASLR |
| Controlled Folder Access off | Ransomware can write to documents freely | Enables CFA |
| Potentially unwanted app protection off | PUA/adware not blocked | Enables PUA protection |
| Defender network protection off | Malicious URLs not blocked at network level | Enables network protection |

### macOS Hardening

| Check | What it detects | Fix available |
|---|---|---|
| FileVault off | Disk unencrypted — readable if Mac is stolen | Info — enable in System Settings |
| Gatekeeper disabled | Unsigned/unnotarised apps run without warning | `spctl --master-enable` |
| System Integrity Protection (SIP) disabled | Root can modify protected system files | Info — re-enable via Recovery Mode |
| Guest user account enabled | Unauthenticated local access | Disables via defaults write |
| Screen lock never triggered | Physical access = full access | Sets 5-minute idle lock |
| Application Firewall off | No app-level inbound filtering | Enables via socketfilterfw |
| Firewall stealth mode off | Mac responds to unsolicited network probes | Enables stealth mode |
| Background security updates disabled | System won't auto-patch vulnerabilities | Enables automatic updates |
| XProtect bundle missing | macOS built-in malware signatures absent | Info |

### Linux Hardening

| Check | What it detects | Fix available |
|---|---|---|
| AppArmor not loaded | Mandatory access control not enforcing | Info |
| SELinux permissive or disabled | MAC not enforcing policies | Info |
| TCP SYN cookies disabled | Vulnerable to SYN flood DoS attacks | `sysctl net.ipv4.tcp_syncookies=1` |
| ASLR not set to full randomisation | Memory layout predictable — aids exploits | `sysctl kernel.randomize_va_space=2` |
| dmesg readable by all users | Kernel addresses leak to unprivileged users | Sets `kernel.dmesg_restrict=1` |
| Core dumps permitted for setuid processes | Sensitive memory can be dumped to disk | Sets `fs.suid_dumpable=0` |
| Kernel pointer leaks not restricted | `/proc` leaks kernel addresses | Sets `kptr_restrict=2` |
| Unattended security upgrades off | System won't auto-patch CVEs | Installs/enables unattended-upgrades |
| fail2ban not running | No brute-force protection on SSH | Starts fail2ban service |
| auditd not running | No kernel-level audit trail | Info |
| SSH permits root login | Root accessible directly over network | Sets `PermitRootLogin no` in sshd_config |

---

## Benchmark Tab

Gullwing includes a pure-Python system benchmark with no external dependencies. Results are graded S through F:

| Tier | Meaning |
|---|---|
| S | Exceptional — enthusiast-grade hardware |
| A | Above average — smooth for all workloads |
| B | Solid — meets expectations |
| C | Below average — may bottleneck under load |
| D / F | Underperforming — investigate thermals or hardware |

Tests: SHA-256 throughput (CPU hash), trigonometric Mop/s (CPU float), memory bandwidth, and sequential disk write speed.

---

## Overclocking Advisory Tab

Gullwing can detect and report on overclocking opportunities for CPU, GPU, RAM, and network cards. It **never automates clock or voltage changes** — all findings are advisory only.

**MSI Mode** (Message Signalled Interrupts) is the one exception where a registry fix is offered, because it is a driver-level interrupt routing change with no voltage or frequency implications.

Every overclocking finding displays a risk warning. Do not act on these findings unless you understand what you are doing.

---

## Safe by Design

Every fix Gullwing applies is a local shell command, PowerShell command, or registry write. There are no:
- API calls or cloud connections
- Telemetry or analytics
- Stored credentials or secrets

The Fix button shows you the exact command it will run, and you are always in control:

> **What's reversible, honestly:** most security and config changes can be reverted in one click; file deletions (Cleaner) and some Windows changes (registry/services) cannot. See [GETTING-STARTED.md](GETTING-STARTED.md#4-revert--what-it-does-and-doesnt-cover) for the full picture.

- **Snapshot & Revert.** Before applying fixes, Gullwing snapshots the affected config (SSH, firewall rules, sysctl, hosts) **to disk** — so if the app is closed or crashes mid-fix, it offers to finish the rollback on next launch. **Revert Session** rolls back everything you changed this session. Cleaner deletions are marked **"Cannot be undone"** rather than pretending they're reversible, and on Windows the snapshot covers the hosts file (registry/service tweaks aren't tracked, so those fixes are applied as non-revertable).
- **Re-validated remediation.** Applying fixes from a saved report (`gullwing remediate`) re-checks every command against a fresh scan first — a tampered report can't smuggle in commands the live system doesn't actually call for.
- **Accept Risk.** Dismiss a finding you've reviewed and don't want to fix — it won't nag you on the next scan.
- **Copy Commands.** Prefer to run things yourself? Copy the exact commands and paste them into your own terminal.
- **Disk-space pre-flight.** Fixes that write to disk warn you first if space is critically low.

---

## What's New in v1.1.3

- **🧾 Now properly open-source.** Added an explicit MIT `LICENSE` so the code you can read is also code you can legally fork, redistribute, and build on.
- **🛡️ Tamper-proof remediation.** `gullwing remediate` now re-validates every command in a saved report against a fresh live scan before running it — a hand-edited report can't smuggle in commands the system doesn't actually call for, even under `--all --yes`.
- **🪟 Clearer Windows revert scope.** After applying fixes, Gullwing states plainly that Windows registry/service changes aren't covered by Revert Session (use System Restore), so the Revert button never over-promises.
- **📖 First-run guide.** A new [GETTING-STARTED.md](GETTING-STARTED.md) explains scanning, scoring, how Fix prompts you, and exactly what Revert can and can't undo. Signing/auto-update path documented in [docs/RELEASE-SIGNING.md](docs/RELEASE-SIGNING.md).

---

## What's New in v1.1.2

- **🔒 Security: closed an admin-level command-injection bug.** A maliciously *named* file in a Windows temp directory (the exact thing the malware scanner flags) could break out of the elevated fix command and run as Administrator when the user clicked **Fix**. Every fix command now routes filesystem-, process-, and registry-derived values through strict PowerShell/POSIX quoting, and a dedicated test suite plants adversarial filenames to keep it that way.
- **🪟 Correct per-OS data locations.** Snapshots, scan history, and revert manifests now live where each OS expects them — `%APPDATA%\gullwing` on Windows, `~/Library/Application Support/gullwing` on macOS, XDG paths on Linux — instead of a Linux-style hidden folder everywhere.
- **💽 Cross-platform disk-space pre-flight.** The low-space warning now checks the drive you actually live on rather than a hardcoded `/`, so it works on Windows too.

---

## What's New in v1.1.1

- **🪶 New gold design system.** A refreshed shell built on a single source-of-truth theme: warm gold accent, teal data highlights, refined surface/border hierarchy, and bundled OFL fonts (Space Grotesk, IBM Plex Sans, JetBrains Mono). The header is now a clean frame carrying the Gullwing gull mark, with a left navigation rail replacing the old tab strip.
- **✨ Real app icon.** A generated Gullwing mark ships as a full icon bundle — `.ico` for Windows, `.icns` for macOS, multi-resolution PNGs, and an in-app header mark — so the app looks the part in the taskbar, dock, and Start menu.
- **🎯 Honest scoring.** Findings that have no one-click fix (BIOS-only settings, informational notes) no longer drag down your overall score. Apply what Gullwing can fix and a top grade is always within reach.
- **💾 Crash-safe revert.** Pre-fix snapshots are written to disk atomically. If Gullwing is closed or killed mid-fix, it detects the interrupted session on next launch and offers to complete the rollback.
- **🧹 Truthful reversibility.** Cleaner deletions are now flagged **"Cannot be undone"** instead of implying they can be reverted, and the fix flow refuses to proceed if it genuinely couldn't capture the state it would need to roll back.
- **🪟 Windows fix reliability.** Fixes no longer fail with "could not capture the current system state" on Windows and macOS — the snapshot layer is platform-aware and only blocks a fix when a rollback would truly be impossible.

---

## Requirements

| Platform | Requirements |
|---|---|
| Windows | Python 3.9+, tkinter (included with standard Python) |
| macOS | Python 3.9+, tkinter (`brew install python-tk`) |
| Linux | Python 3.9+, `python3-tk` (`sudo apt install python3-tk`) |

---

*Gullwing v1.1.3 — built for people who want their machine to perform.*
