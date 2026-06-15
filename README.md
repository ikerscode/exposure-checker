# Exposure Checker v1.0.6

**Scan · Optimize · Protect · Clean** — a fully local, offline desktop tool for Windows, macOS, and Linux.  
No API keys. No cloud. No telemetry. Everything runs on your machine.

---

## Quick Start

### Windows
Double-click `exposure_checker_ui.py` — it will ask for admin rights, then open.

### macOS
```bash
python3 exposure_checker_ui.py
```

### Linux
1. Install Python + Tkinter if you haven't already:
   ```bash
   sudo apt install python3-tk -y
   ```
2. Double-click **`ExposureChecker.desktop`** → click **Allow Launching** the first time.  
   Or from terminal:
   ```bash
   bash run.sh
   ```

---

## What It Does

The app has three scan tabs. Each finding shows its severity, a plain-English explanation, and a **Fix** button where a fix is available.

| Severity | Meaning |
|---|---|
| 🔴 CRITICAL | Immediate risk — fix now |
| 🟠 HIGH | Serious issue |
| 🟡 MEDIUM | Should be addressed |
| 🔵 REVIEW | Investigate and decide |
| ⚪ INFO | Informational — no auto-fix |

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
| No active firewall | Win / macOS / Linux | 🔴 Alerts — no inbound packet filtering |
| Windows Firewall disabled on all profiles | Windows | 🟠 Alerts to re-enable via Windows Security |
| ufw installed but inactive | Linux | 🟠 Enables ufw |
| No firewall detected | macOS | 🟠 Directs to System Settings → Firewall |

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
| Docker socket world-writable | Linux | 🔴 Critical — equivalent to giving root to anyone |
| Docker socket world-readable | Linux | 🟠 Restricts socket permissions |
| Docker image CVE scan (Trivy) | Linux | Scans local images for known CVEs if Trivy is installed |

### Malware Indicators

| Check | Platforms | What it fixes |
|---|---|---|
| Windows Defender scan + heuristic indicators | Windows | Runs Defender quick scan; checks for ld.so.preload, unusual SUID |
| macOS heuristic malware indicators | macOS | Checks LaunchAgents/Daemons for suspicious entries |

---

## Protection Tab

### Windows Hardening

| Check | What it detects | Fix available |
|---|---|---|
| TPM 2.0 not activated | TPM present but not enabled in BIOS | Info only |
| Secure Boot disabled | UEFI Secure Boot off | Info — requires BIOS change |
| Memory Integrity (HVCI / Core Isolation) off | Hypervisor-protected code integrity disabled | ✅ Enables via registry + reboot |
| UAC set to never notify | User Account Control fully disabled | ✅ Re-enables UAC prompt |
| AutoRun not fully disabled | USB/disc autorun can execute code silently | ✅ Sets NoDriveTypeAutoRun=0xFF |
| Defender Real-Time Protection off | 🔴 Live malware scanning disabled | ✅ Re-enables via PowerShell |
| Defender script scanning disabled | 🟠 PowerShell/script malware won't be caught | ✅ Re-enables script scanning |
| SMBv1 enabled | Legacy protocol exploited by WannaCry/NotPetya | ✅ Disables SMBv1 |
| Remote Desktop enabled | RDP exposed — common brute-force target | Info — disable if not needed |
| Remote Assistance enabled | Allows unsolicited remote access | Info |
| Guest account enabled | Unauthenticated local access | ✅ Disables guest account |
| BitLocker not enabled on system drive | Drive readable if physically removed | Info — enable in Windows Security |
| Exploit Protection Force ASLR off | Memory layout not randomised | ✅ Enables Force ASLR |
| Controlled Folder Access off | Ransomware can write to documents freely | ✅ Enables CFA |
| Potentially unwanted app protection off | PUA/adware not blocked | ✅ Enables PUA protection |
| Defender network protection off | Malicious URLs not blocked at network level | ✅ Enables network protection |

### macOS Hardening

| Check | What it detects | Fix available |
|---|---|---|
| FileVault off | 🟠 Disk unencrypted — readable if Mac is stolen | Info — enable in System Settings |
| Gatekeeper disabled | 🟠 Unsigned/unnotarised apps run without warning | ✅ `spctl --master-enable` |
| System Integrity Protection (SIP) disabled | 🟠 Root can modify protected system files | Info — re-enable via Recovery Mode |
| Guest user account enabled | Unauthenticated local access | ✅ Disables via defaults write |
| Screen lock never triggered | Physical access = full access | ✅ Sets 5-minute idle lock |
| Application Firewall off | 🟠 No app-level inbound filtering | ✅ Enables via socketfilterfw |
| Firewall stealth mode off | Mac responds to unsolicited network probes | ✅ Enables stealth mode |
| Background security updates disabled | System won't auto-patch vulnerabilities | ✅ Enables automatic updates |
| XProtect bundle missing | macOS built-in malware signatures absent | Info |

### Linux Hardening

| Check | What it detects | Fix available |
|---|---|---|
| AppArmor not loaded | Mandatory access control not enforcing | Info |
| SELinux permissive or disabled | MAC not enforcing policies | Info |
| TCP SYN cookies disabled | 🟠 Vulnerable to SYN flood DoS attacks | ✅ `sysctl net.ipv4.tcp_syncookies=1` |
| ASLR not set to full randomisation | Memory layout predictable — aids exploits | ✅ `sysctl kernel.randomize_va_space=2` |
| dmesg readable by all users | Kernel addresses leak to unprivileged users | ✅ Sets `kernel.dmesg_restrict=1` |
| Core dumps permitted for setuid processes | Sensitive memory can be dumped to disk | ✅ Sets `fs.suid_dumpable=0` |
| Kernel pointer leaks not restricted | `/proc` leaks kernel addresses | ✅ Sets `kptr_restrict=2` |
| Unattended security upgrades off | System won't auto-patch CVEs | ✅ Installs/enables unattended-upgrades |
| fail2ban not running | No brute-force protection on SSH | ✅ Starts fail2ban service |
| auditd not running | No kernel-level audit trail | Info |
| SSH permits root login | 🟠 Root accessible directly over network | ✅ Sets `PermitRootLogin no` in sshd_config |

---

## All Fixes Are Local

Every fix the app applies is a local shell command, PowerShell command, or registry write. There are no:
- API calls or cloud connections
- Telemetry or analytics
- Stored credentials or secrets

The Fix button shows you the exact command it will run. You are always in control.

---

## Requirements

| Platform | Requirements |
|---|---|
| Windows | Python 3.8+, tkinter (included with standard Python) |
| macOS | Python 3.8+, tkinter (`brew install python-tk`) |
| Linux | Python 3.8+, `python3-tk` (`sudo apt install python3-tk`) |

---

*Exposure Checker v1.0.6 — built for gamers who take their rig seriously.*
