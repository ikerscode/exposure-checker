"""
Overclocking advisory — detection and guidance only. NO automated changes.

╔══════════════════════════════════════════════════════════════════════════════╗
║  ⚠  OVERCLOCKING RISK — READ BEFORE ACTING ON ANY FINDING IN THIS MODULE  ║
║                                                                              ║
║  • Overclocking voids manufacturer warranties on CPU, GPU, and motherboard. ║
║  • Unstable voltages or frequencies can cause data corruption, system        ║
║    crashes (BSODs / kernel panics), or PERMANENT hardware damage.            ║
║  • Heat output rises sharply with OC — inadequate cooling accelerates        ║
║    silicon degradation and can kill components in minutes.                   ║
║  • Every CPU, GPU, and RAM kit is unique (silicon lottery). Safe settings   ║
║    for one chip may destroy another of the same model.                       ║
║  • DO NOT overclock if you are not confident in what you are doing.         ║
║  • Always: stress-test after every change, monitor temps in real time,       ║
║    and increase settings gradually — never in large jumps.                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

This module only reads system state and gives advisory findings. It will never
write to the registry, run powercfg, or modify BIOS settings automatically.
"""

import glob
import json as _json
import os
import re
import shutil
import subprocess

from .._core import _OS, _ps, _truncate

# ── Risk banner injected into every OC finding's why field ────────────────────

_RISK = (
    "⚠ OC RISK: Overclocking can void warranties, cause data loss, system "
    "instability, or permanent hardware damage. Ensure adequate cooling, stress-"
    "test after every change, and increase settings gradually. Do NOT proceed "
    "unless you fully understand what you are doing."
)


def _risk(text: str) -> str:
    return f"{text}\n\n{_RISK}"


# ── CPU — Windows ──────────────────────────────────────────────────────────────

def _oc_cpu_windows(reporter) -> int:
    n = 0

    # ── CPU identity & clock ───────────────────────────────────────────────────
    cpu_out, rc = _ps(
        "Get-WmiObject Win32_Processor | "
        "Select-Object Name, MaxClockSpeed, CurrentClockSpeed, NumberOfCores, "
        "NumberOfLogicalProcessors | ConvertTo-Json",
        timeout=20,
    )
    cpu_name = current_mhz = max_mhz = cores = threads = None
    if rc == 0 and cpu_out.strip():
        try:
            d = _json.loads(cpu_out)
            if isinstance(d, list):
                d = d[0]
            cpu_name    = str(d.get("Name", "")).strip()
            max_mhz     = int(d.get("MaxClockSpeed") or 0)
            current_mhz = int(d.get("CurrentClockSpeed") or 0)
            cores       = int(d.get("NumberOfCores") or 0)
            threads     = int(d.get("NumberOfLogicalProcessors") or 0)
        except Exception:
            pass

    if cpu_name:
        reporter.finding(
            "INFO",
            f"CPU detected: {_truncate(cpu_name, 70)} "
            f"({cores}C/{threads}T, base ~{max_mhz} MHz)",
            _risk(
                "Identifying your CPU is the first step in evaluating OC potential. "
                "Intel K/KF/KS and AMD X/XT CPUs are unlocked for multiplier OC. "
                "Intel non-K and AMD non-X CPUs have limited or no OC headroom."
            ),
            "No action required. This is informational. "
            "Intel: use Intel XTU or BIOS for OC. AMD: use Ryzen Master or BIOS PBO.",
        )

    # ── Intel Turbo Boost ──────────────────────────────────────────────────────
    is_intel = cpu_name and "intel" in cpu_name.lower()
    is_amd   = cpu_name and "amd"   in cpu_name.lower()

    if is_intel:
        turbo_disabled, _ = _ps(
            "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Processor\\0' "
            "-Name PerfBoostMode -ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty PerfBoostMode",
        )
        try:
            val = int(turbo_disabled.strip())
        except Exception:
            val = None

        if val == 0:
            reporter.finding(
                "REVIEW",
                "Intel Turbo Boost appears disabled",
                _risk(
                    "Turbo Boost lets Intel CPUs exceed their base clock when thermal "
                    "and power headroom allows — often 20–40% above base on modern chips. "
                    "Disabling it can halve single-threaded game performance."
                ),
                "Re-enable in BIOS: Advanced CPU Configuration → Intel Turbo Boost Technology → Enabled. "
                "Or via power plan: powercfg → Processor performance boost mode → Aggressive.",
            )
            n += 1
        elif val is not None:
            reporter.ok("Intel Turbo Boost is active")

        # ── Intel OC headroom advisory ─────────────────────────────────────────
        if cpu_name and any(s in cpu_name for s in ("K ", "KF", "KS", " K\t")):
            reporter.finding(
                "INFO",
                "Unlocked Intel K-series CPU detected — manual OC possible",
                _risk(
                    "K/KF/KS CPUs have an unlocked multiplier, enabling per-core frequency "
                    "OC via BIOS or Intel XTU. Common gains: +300–600 MHz on P-cores, "
                    "+5–15% in single-threaded game workloads. Requires a Z-series motherboard."
                ),
                "Tools: Intel Extreme Tuning Utility (XTU) for Windows GUI OC, "
                "or BIOS → AI Tweaker / OC Tweaker → CPU ratio override. "
                "Start by disabling power limits (PL1/PL2) before touching multipliers.",
            )
            n += 1

    # ── AMD Precision Boost ────────────────────────────────────────────────────
    if is_amd:
        # Check if running below rated boost via comparison (rough)
        reporter.finding(
            "INFO",
            "AMD CPU detected — Precision Boost Overdrive (PBO) available",
            _risk(
                "PBO allows the CPU to boost above its rated all-core clock when "
                "thermal and power headroom exists. Curve Optimizer (per-core negative "
                "voltage offset) often yields +100–200 MHz boost for free with lower temps. "
                "Manual PBO limits, scalar, and CO require careful tuning per chip."
            ),
            "Tools: AMD Ryzen Master (Windows GUI) for live tuning without reboot, "
            "or BIOS → AMD Overclocking → PBO → Enable. "
            "Curve Optimizer: start with -10 all-core, test stability, push further cautiously.",
        )
        n += 1

    # ── CPU temperature (thermal headroom for OC) ──────────────────────────────
    temp_out, rc = _ps(
        "Get-WmiObject -Namespace 'root/wmi' -Class MSAcpi_ThermalZoneTemperature "
        "-ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty CurrentTemperature",
        timeout=15,
    )
    if rc == 0 and temp_out.strip():
        try:
            # WMI returns tenths of Kelvin
            raw_vals = [int(v.strip()) for v in temp_out.strip().splitlines() if v.strip().isdigit()]
            if raw_vals:
                max_celsius = max((v - 2732) / 10 for v in raw_vals)
                if max_celsius >= 90:
                    reporter.finding(
                        "HIGH",
                        f"CPU thermal zone at {max_celsius:.0f}°C — no OC headroom, throttling likely",
                        _risk(
                            "At ≥90°C the CPU is approaching or hitting its thermal junction limit "
                            "(Tjmax). The chip will reduce clocks to protect itself (thermal throttling), "
                            "and overclocking at this temperature risks permanent damage."
                        ),
                        "Do NOT overclock. Improve cooling first: clean dust filters, "
                        "repaste thermal compound (every 3–5 years), add case airflow, "
                        "or upgrade to a larger air cooler or AIO liquid cooler.",
                    )
                    n += 1
                elif max_celsius >= 75:
                    reporter.finding(
                        "REVIEW",
                        f"CPU thermal zone at {max_celsius:.0f}°C — limited OC headroom at load",
                        _risk(
                            "75–89°C is within spec at full load but leaves little margin for OC. "
                            "Higher clocks and voltages will push temps closer to Tjmax."
                        ),
                        "Ensure case airflow is adequate before OC'ing. Monitor temps under "
                        "sustained load (Prime95, Cinebench multicore) before pushing clocks.",
                    )
                    n += 1
                else:
                    reporter.ok(f"CPU thermal zone: {max_celsius:.0f}°C — adequate headroom for OC consideration")
        except Exception:
            pass

    return n


# ── CPU — Linux ────────────────────────────────────────────────────────────────

def _oc_cpu_linux(reporter) -> int:
    n = 0

    # ── CPU name ───────────────────────────────────────────────────────────────
    cpu_name = None
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    cpu_name = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass

    if cpu_name:
        reporter.finding(
            "INFO",
            f"CPU: {_truncate(cpu_name, 70)}",
            _risk(
                "Linux exposes CPU frequency scaling via /sys/devices/system/cpu/. "
                "Overclocking on Linux is possible via BIOS/UEFI (Intel K/AMD X chips) "
                "or kernel params; the OS itself does not restrict OC."
            ),
            "No action required. OC must be configured in BIOS/UEFI, not the OS.",
        )

    is_intel = cpu_name and "intel" in cpu_name.lower()
    is_amd   = cpu_name and "amd"   in cpu_name.lower()

    # ── Intel Turbo ────────────────────────────────────────────────────────────
    no_turbo_path = "/sys/devices/system/cpu/intel_pstate/no_turbo"
    if os.path.exists(no_turbo_path):
        try:
            with open(no_turbo_path) as f:
                val = f.read().strip()
            if val == "1":
                reporter.finding(
                    "REVIEW",
                    "Intel Turbo Boost is disabled (no_turbo=1)",
                    _risk(
                        "intel_pstate/no_turbo=1 prevents the CPU from boosting above its base "
                        "clock. This can halve single-threaded performance."
                    ),
                    "Re-enable: echo 0 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo\n"
                    "To persist across reboots add 'intel_pstate.no_turbo=0' to GRUB_CMDLINE_LINUX "
                    "in /etc/default/grub, then run update-grub.",
                    fix_cmds=["echo 0 | tee /sys/devices/system/cpu/intel_pstate/no_turbo"],
                )
                n += 1
            else:
                reporter.ok("Intel Turbo Boost is enabled")
        except OSError:
            pass

    # ── AMD Boost ──────────────────────────────────────────────────────────────
    amd_boost_path = "/sys/devices/system/cpu/cpufreq/boost"
    if os.path.exists(amd_boost_path):
        try:
            with open(amd_boost_path) as f:
                val = f.read().strip()
            if val == "0":
                reporter.finding(
                    "REVIEW",
                    "AMD CPU boost is disabled",
                    _risk(
                        "AMD's boost control at /sys/devices/system/cpu/cpufreq/boost=0 "
                        "prevents all cores from exceeding their base frequency."
                    ),
                    "Re-enable: echo 1 | sudo tee /sys/devices/system/cpu/cpufreq/boost",
                    fix_cmds=["echo 1 | tee /sys/devices/system/cpu/cpufreq/boost"],
                )
                n += 1
            else:
                reporter.ok("AMD CPU boost is enabled")
        except OSError:
            pass

    # ── CPU governor ───────────────────────────────────────────────────────────
    gov_path = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
    if os.path.exists(gov_path):
        try:
            with open(gov_path) as f:
                gov = f.read().strip()
            if gov == "powersave" and is_intel:
                reporter.finding(
                    "REVIEW",
                    f"CPU governor is '{gov}' — Intel CPUs may under-clock in this mode",
                    _risk(
                        "The 'powersave' governor with intel_pstate can still boost on modern "
                        "kernels, but on older kernels it may cap frequency at base clock, "
                        "hurting single-threaded game performance."
                    ),
                    "Switch to performance governor: "
                    "echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor\n"
                    "Or install cpupower: sudo cpupower frequency-set -g performance",
                    fix_cmds=[
                        "for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; "
                        "do echo performance | tee \"$f\"; done"
                    ],
                )
                n += 1
            else:
                reporter.ok(f"CPU governor: {gov}")
        except OSError:
            pass

    # ── AMD PBO advisory ───────────────────────────────────────────────────────
    if is_amd:
        reporter.finding(
            "INFO",
            "AMD CPU — Precision Boost Overdrive (PBO) and Curve Optimizer available",
            _risk(
                "PBO lets the CPU exceed its rated boost clock when thermal and power "
                "headroom exists. Curve Optimizer applies a per-core negative voltage "
                "offset, often yielding +100–200 MHz boost at LOWER temps. "
                "ryzenadj (Linux) allows runtime PBO limit adjustments without rebooting."
            ),
            "Tools: BIOS → AMD Overclocking → PBO → Enable (persistent). "
            "Linux runtime: https://github.com/FlyGoat/RyzenAdj — use cautiously. "
            "Curve Optimizer: BIOS only; start at −10 all-core, test with Prime95, push slowly.",
        )
        n += 1

    # ── CPU temps ──────────────────────────────────────────────────────────────
    temp_files = glob.glob("/sys/class/thermal/thermal_zone*/temp")
    if temp_files:
        try:
            temps = []
            for tf in temp_files:
                with open(tf) as f:
                    temps.append(int(f.read().strip()) / 1000)
            max_c = max(temps)
            if max_c >= 90:
                reporter.finding(
                    "HIGH",
                    f"CPU thermal zone at {max_c:.0f}°C — critical, no OC headroom",
                    _risk(
                        "≥90°C means the CPU is at or near Tjmax. Thermal throttling is "
                        "actively reducing performance. Overclocking here risks hardware damage."
                    ),
                    "Improve cooling before any OC attempt. Clean dust, repaste, add airflow.",
                )
                n += 1
            elif max_c >= 75:
                reporter.finding(
                    "REVIEW",
                    f"CPU thermal zone at {max_c:.0f}°C — limited OC margin",
                    _risk("75–89°C under load leaves little thermal margin for higher frequencies."),
                    "Ensure cooling is adequate. Stress-test (stress-ng, Prime95) and monitor "
                    "before pushing clocks.",
                )
                n += 1
            else:
                reporter.ok(f"CPU thermals: {max_c:.0f}°C — good headroom for OC consideration")
        except Exception:
            pass

    return n


# ── CPU — macOS ────────────────────────────────────────────────────────────────

def _oc_cpu_macos(reporter) -> int:
    n = 0

    try:
        name = subprocess.check_output(
            ["sysctl", "-n", "machdep.cpu.brand_string"],
            timeout=5, text=True, stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        name = None

    if name:
        is_apple_silicon = "apple" in name.lower()
        reporter.finding(
            "INFO",
            f"CPU: {_truncate(name, 70)}",
            _risk(
                "Apple Silicon (M-series) chips are fully integrated SoCs — there is no "
                "supported overclocking path. The frequency and voltage are managed entirely "
                "by Apple's firmware and cannot be changed by the user. "
                "Intel Mac CPUs can be OC'd only via BIOS, which is not exposed on Macs — "
                "so overclocking is effectively not possible on any Mac."
            ) if is_apple_silicon else _risk(
                "Intel Mac CPUs run at Apple-set firmware clocks with no user-accessible "
                "OC controls. Turbo Boost can be disabled/enabled via third-party tools "
                "(Turbo Boost Switcher) but cannot be increased beyond Intel spec."
            ),
            "No overclocking action available on macOS. "
            "Performance tuning is limited to power-plan and cooling optimisations.",
        )
        if not is_apple_silicon:
            reporter.finding(
                "INFO",
                "Intel Mac — Turbo Boost toggle available (no frequency increase)",
                _risk(
                    "Turbo Boost Switcher (free, third-party) can disable Turbo to reduce "
                    "heat on thin MacBooks, or ensure it stays enabled for performance. "
                    "This is NOT overclocking — it only enables/disables Apple's spec boost."
                ),
                "Install Turbo Boost Switcher from rugarciap.com to toggle Turbo Boost. "
                "Overclocking above spec is not possible on Intel Macs.",
            )
            n += 1

    return n


# ── GPU — all platforms via nvidia-smi ────────────────────────────────────────

def _oc_gpu_nvidia(reporter) -> int:
    n = 0
    if not shutil.which("nvidia-smi"):
        return 0

    query = (
        "index,name,clocks.current.graphics,clocks.max.graphics,"
        "clocks.current.memory,clocks.max.memory,"
        "temperature.gpu,power.draw,enforced.power.limit,power.limit"
    )
    try:
        out = subprocess.check_output(
            ["nvidia-smi", f"--query-gpu={query}", "--format=csv,noheader,nounits"],
            timeout=15, text=True, stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return 0

    for line in out.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 10:
            continue
        try:
            idx          = parts[0]
            name         = parts[1]
            cur_core     = float(parts[2]) if parts[2] not in ("N/A", "[N/A]") else None
            max_core     = float(parts[3]) if parts[3] not in ("N/A", "[N/A]") else None
            cur_mem      = float(parts[4]) if parts[4] not in ("N/A", "[N/A]") else None
            max_mem      = float(parts[5]) if parts[5] not in ("N/A", "[N/A]") else None
            temp         = float(parts[6]) if parts[6] not in ("N/A", "[N/A]") else None
            power_draw   = float(parts[7]) if parts[7] not in ("N/A", "[N/A]") else None
            enforced_pl  = float(parts[8]) if parts[8] not in ("N/A", "[N/A]") else None
            default_pl   = float(parts[9]) if parts[9] not in ("N/A", "[N/A]") else None
        except (ValueError, IndexError):
            continue

        label_prefix = f"GPU {idx} ({_truncate(name, 40)})"

        # ── GPU identity + OC advisory ─────────────────────────────────────────
        reporter.finding(
            "INFO",
            f"{label_prefix} — NVIDIA GPU OC advisory",
            _risk(
                f"Detected: {name}. "
                "NVIDIA GPUs support core clock offset (+0 to +200 MHz typical), "
                "memory clock offset (+0 to +1000 MHz typical), and power limit raise "
                "(+10–25% on most cards). Gains vary: +5–15% in GPU-bound workloads. "
                "Raising power limit first (in MSI Afterburner) is the safest first step."
            ),
            "Tools: MSI Afterburner (GPU OC, free) or EVGA Precision X1. "
            "Process: raise power limit → test stability (FurMark / Unigine Heaven) → "
            "raise core offset +25 MHz at a time → test → raise memory offset. "
            "DO NOT exceed 85°C GPU temp under sustained load.",
        )
        n += 1

        # ── Thermal headroom ──────────────────────────────────────────────────
        if temp is not None:
            if temp >= 88:
                reporter.finding(
                    "HIGH",
                    f"{label_prefix}: GPU at {temp:.0f}°C — critical, no OC headroom",
                    _risk(
                        f"At {temp:.0f}°C the GPU is near or above safe sustained operating "
                        "temperature. NVIDIA cards throttle at ~83–87°C. Overclocking here "
                        "will worsen throttling and risks reducing GPU lifespan."
                    ),
                    "Do NOT overclock. Clean GPU heatsink/fans, improve case airflow, "
                    "or repaste GPU die (advanced). Consider undervolting instead — "
                    "it reduces temps while often maintaining or improving clock speeds.",
                )
                n += 1
            elif temp >= 75:
                reporter.finding(
                    "REVIEW",
                    f"{label_prefix}: GPU at {temp:.0f}°C — limited OC thermal margin",
                    _risk(
                        f"At {temp:.0f}°C under load there is limited margin before throttling. "
                        "OC will push temps higher. Consider a custom fan curve before OC'ing."
                    ),
                    "Set an aggressive fan curve in MSI Afterburner before pushing clocks. "
                    "Target ≤80°C under sustained gaming load.",
                )
                n += 1
            else:
                reporter.ok(f"{label_prefix}: {temp:.0f}°C — good thermal headroom for OC")

        # ── Power limit status ─────────────────────────────────────────────────
        if power_draw is not None and enforced_pl is not None and enforced_pl > 0:
            utilisation = power_draw / enforced_pl
            if utilisation >= 0.97:
                reporter.finding(
                    "REVIEW",
                    f"{label_prefix}: power-limited at {power_draw:.0f} W / {enforced_pl:.0f} W "
                    f"({utilisation*100:.0f}%) — raising power limit is step 1 of GPU OC",
                    _risk(
                        "The GPU is drawing its full power budget. Raising the power limit "
                        "(+10–25%) in MSI Afterburner unlocks additional boost headroom "
                        "with no other changes. This is the safest, most effective first "
                        "OC step on NVIDIA cards and usually yields +2–5% performance for free."
                    ),
                    "In MSI Afterburner: move the Power Limit slider to maximum → Apply. "
                    "Stability-test for 20 minutes. Only then adjust core/memory clocks.",
                )
                n += 1

        # ── Current clock vs boost clock ──────────────────────────────────────
        # Only flag if power_draw suggests the GPU is actually under load (>10 W).
        # At idle, NVIDIA GPUs drop to 135–300 MHz regardless of boost clock.
        if (cur_core is not None and max_core is not None and max_core > 0
                and power_draw is not None and power_draw > 10):
            ratio = cur_core / max_core
            if ratio < 0.85:
                reporter.finding(
                    "REVIEW",
                    f"{label_prefix}: GPU core at {cur_core:.0f} / {max_core:.0f} MHz "
                    f"({ratio*100:.0f}% of boost) under load — possible throttle",
                    _risk(
                        "The GPU is running significantly below its advertised boost clock "
                        "while drawing meaningful power. This usually indicates thermal or "
                        "power throttling. OC'ing a throttled card will not help — "
                        "fix the underlying cause first."
                    ),
                    "Check GPU temperature and power utilisation above. "
                    "Consider a custom fan curve in MSI Afterburner to lower temps, "
                    "or undervolting to reduce power draw at the same clock.",
                )
                n += 1

        # ── Memory OC advisory ────────────────────────────────────────────────
        if cur_mem is not None and max_mem is not None:
            reporter.finding(
                "INFO",
                f"{label_prefix}: VRAM at {cur_mem:.0f} MHz (max rated {max_mem:.0f} MHz) — memory OC available",
                _risk(
                    "VRAM overclocking can yield +5–15% in VRAM-bandwidth-limited scenes "
                    "(4K, high-res textures, ray tracing). GDDR6X benefits more than GDDR6. "
                    "Memory OC is generally more stable than core OC but can cause "
                    "visual corruption (artifacts) if pushed too far."
                ),
                "In MSI Afterburner: raise Memory Clock offset +100 MHz → Apply → run "
                "FurMark or a demanding game for 15 min → check for visual artifacts. "
                "If stable, add another +100 MHz and repeat. Stop at first sign of corruption.",
            )
            n += 1

    return n


def _oc_gpu_amd_linux(reporter) -> int:
    n = 0
    if not shutil.which("rocm-smi"):
        return 0

    try:
        out = subprocess.check_output(
            ["rocm-smi", "--showclocks", "--showtemp"],
            timeout=15, text=True, stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return 0

    reporter.finding(
        "INFO",
        "AMD GPU detected — overclocking advisory",
        _risk(
            "AMD GPUs on Linux support OC via CoreCtrl (GUI) or direct sysfs writes to "
            "/sys/class/drm/card*/device/pp_od_clk_voltage. "
            "Voltage, core clock, and memory clock can each be tuned independently. "
            "Undervolting (same clock, lower voltage) is the safest first step — "
            "it reduces power draw and temps with no stability risk on most cards."
        ),
        "Tools: CoreCtrl (Linux GUI, free) or direct sysfs. "
        "First step: enable manual performance level — "
        "echo manual | sudo tee /sys/class/drm/card0/device/power_dpm_force_performance_level\n"
        "Then use CoreCtrl or rocm-smi --setoverdrive to tune.",
    )
    n += 1
    return n


# ── RAM overclocking advisory ─────────────────────────────────────────────────

def _oc_ram(reporter) -> int:
    n = 0

    if _OS == "Windows":
        out, rc = _ps(
            "Get-WmiObject Win32_PhysicalMemory | "
            "Select-Object Speed, ConfiguredClockSpeed, Manufacturer, PartNumber, Capacity | "
            "ConvertTo-Json",
            timeout=20,
        )
        if rc != 0 or not out.strip():
            return 0

        try:
            sticks = _json.loads(out)
            if isinstance(sticks, dict):
                sticks = [sticks]
        except Exception:
            return 0

        total_gb = sum(int(s.get("Capacity") or 0) for s in sticks) // (1024 ** 3)
        stick_count = len(sticks)
        speeds = [int(s.get("Speed") or 0) for s in sticks]
        actual_speeds = [int(s.get("ConfiguredClockSpeed") or 0) for s in sticks]
        rated  = max(speeds)      if speeds        else 0
        actual = max(actual_speeds) if actual_speeds else 0

        if stick_count == 1:
            reporter.finding(
                "REVIEW",
                f"Single RAM stick installed ({total_gb} GB) — dual-channel OC tip",
                _risk(
                    "A single stick runs in single-channel mode, halving memory bandwidth. "
                    "Adding a matching second stick in the paired slot enables dual-channel — "
                    "this is often the single biggest free performance gain available, "
                    "especially on AMD Ryzen which is highly memory-bandwidth sensitive."
                ),
                "Buy a matching RAM kit (same rated speed, same capacity) and install it "
                "in the A2/B2 slots (check your motherboard manual). Enable XMP/EXPO in BIOS.",
            )
            n += 1

        if rated > 0 and actual > 0 and actual < rated * 0.95:
            reporter.finding(
                "REVIEW",
                f"RAM running at {actual} MHz but rated for {rated} MHz — XMP/EXPO not active",
                _risk(
                    "Without XMP (Intel) / EXPO (AMD) / D.O.C.P (ASUS), RAM defaults to "
                    "JEDEC standard (typically 2133–3200 MHz) regardless of its rated speed. "
                    "Enabling the XMP profile is considered safe — it uses the manufacturer's "
                    "tested settings — and is the most accessible OC step for most users. "
                    "However, some motherboard/CPU combinations require manual voltage tweaks "
                    "to stabilise high-speed kits."
                ),
                "Enter UEFI/BIOS → AI Tweaker (ASUS) / OC Tweaker (ASRock) / "
                "A-XMP (MSI) / XMP (Gigabyte) → select XMP/EXPO Profile 1 → Save & Exit. "
                "If the system fails to POST, clear CMOS and try XMP Profile 2 or lower speed.",
            )
            n += 1
        elif actual >= 4800:
            reporter.finding(
                "INFO",
                f"RAM at {actual} MHz — already at enthusiast speeds; tighter timings are next",
                _risk(
                    "At ≥4800 MHz, further performance gains come from tightening primary "
                    "timings (CL, tRCD, tRP, tRAS). This is advanced and requires extensive "
                    "stability testing with MemTest86 and y-cruncher."
                ),
                "Tools: Thaiphoon Burner to read SPD data, DRAM Calculator for Ryzen "
                "(AMD) or Intel Extreme Memory Profile for Intel-platform timing optimisation. "
                "Reduce CL by 1 at a time; run MemTest86 for each change.",
            )
            n += 1
        elif actual > 0:
            reporter.ok(f"RAM running at {actual} MHz (XMP/EXPO active or at JEDEC max)")

    elif _OS == "Linux":
        try:
            out = subprocess.check_output(
                ["sudo", "dmidecode", "--type", "17"],
                timeout=10, text=True, stderr=subprocess.DEVNULL,
            )
            speeds  = [int(m.group(1)) for m in re.finditer(r"Speed:\s+(\d+)\s+MT/s", out)]
            configs = [int(m.group(1)) for m in re.finditer(r"Configured Memory Speed:\s+(\d+)\s+MT/s", out)]
            if speeds and configs:
                rated  = max(speeds)
                actual = max(configs)
                if actual < rated * 0.95:
                    reporter.finding(
                        "REVIEW",
                        f"RAM running at {actual} MT/s but rated for {rated} MT/s — XMP/EXPO not active",
                        _risk(
                            "Enabling XMP/EXPO in BIOS for the rated profile is typically safe "
                            "and often the easiest performance win. See full advisory above."
                        ),
                        "Enter BIOS → enable XMP/EXPO profile. "
                        "Verify stability with: sudo memtester $(free -m | awk '/Mem/{print int($2*0.9)}')M 1",
                    )
                    n += 1
                else:
                    reporter.ok(f"RAM at {actual} MT/s — XMP/EXPO active")
        except Exception:
            pass

    return n


# ── MSI mode — Windows only ───────────────────────────────────────────────────

def _oc_msi_mode_windows(reporter) -> int:
    """
    Check whether GPU and NIC PCI devices have Message Signalled Interrupts enabled.
    MSI reduces DPC latency (a major source of audio glitches and input-lag spikes).
    This is NOT overclocking, but it belongs in the OC/tuning advisory context.
    """
    n = 0

    out, rc = _ps(
        r"""
$results = @()
$targetKeywords = @('nvidia','amd','radeon','geforce','intel.*ethernet',
                    'realtek.*ethernet','killer','broadcom.*network','network adapter',
                    'ethernet','wireless','wi-fi','wlan')
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI' -EA SilentlyContinue |
ForEach-Object {
    Get-ChildItem $_.PSPath -EA SilentlyContinue | ForEach-Object {
        $devPath = $_.PSPath
        $msiPath = "$devPath\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
        if (Test-Path $msiPath) {
            $msi  = (Get-ItemProperty $msiPath -Name MSISupported -EA SilentlyContinue).MSISupported
            $name = (Get-ItemProperty $devPath  -Name FriendlyName -EA SilentlyContinue).FriendlyName
            if ($null -ne $msi -and $name) {
                $lname = $name.ToLower()
                $isTarget = $false
                foreach ($kw in $targetKeywords) { if ($lname -match $kw) { $isTarget = $true; break } }
                if ($isTarget -and $msi -eq 0) { $results += $name }
            }
        }
    }
}
$results -join '||'
        """,
        timeout=30,
    )
    if rc != 0 or not out.strip():
        return 0

    devices = [d.strip() for d in out.strip().split("||") if d.strip()]
    if not devices:
        reporter.ok("MSI mode: enabled on all detected GPU/NIC devices")
        return 0

    for dev in devices:
        reporter.finding(
            "MEDIUM",
            f"MSI mode disabled: {_truncate(dev, 60)}",
            "Message Signalled Interrupts (MSI) give each PCI device its own dedicated "
            "interrupt vector, eliminating contention on the legacy shared IRQ line. "
            "Enabling MSI for GPU and NIC can measurably reduce DPC latency — a common "
            "cause of audio stutters, input-lag spikes, and microstutter in games.",
            "Enable via registry (requires reboot and admin rights). "
            "Easiest method: download MSI Mode Utility (free, by Dword) — it provides "
            "a GUI listing all PCI devices with their MSI status. "
            "Manual method: Device Manager → device → Properties → Details → "
            "Hardware IDs → note VEN/DEV → navigate in regedit to "
            "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\<device>\\<instance>\\"
            "Device Parameters\\Interrupt Management\\MessageSignaledInterruptProperties "
            "→ set MSISupported = 1 (DWORD) → reboot.",
            fix_cmds=[
                r"""
$targetKeywords = @('nvidia','amd','radeon','geforce','intel.*ethernet',
                    'realtek.*ethernet','killer','broadcom.*network','network adapter',
                    'ethernet','wireless','wi-fi','wlan')
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI' -EA SilentlyContinue |
ForEach-Object {
    Get-ChildItem $_.PSPath -EA SilentlyContinue | ForEach-Object {
        $devPath = $_.PSPath
        $msiPath = "$devPath\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
        if (Test-Path $msiPath) {
            $msi  = (Get-ItemProperty $msiPath -Name MSISupported -EA SilentlyContinue).MSISupported
            $name = (Get-ItemProperty $devPath  -Name FriendlyName -EA SilentlyContinue).FriendlyName
            if ($null -ne $msi -and $name) {
                $lname = $name.ToLower()
                $isTarget = $false
                foreach ($kw in $targetKeywords) { if ($lname -match $kw) { $isTarget = $true; break } }
                if ($isTarget -and $msi -eq 0) {
                    Set-ItemProperty $msiPath -Name MSISupported -Value 1 -Type DWord
                    Write-Output "Enabled MSI for: $name"
                }
            }
        }
    }
}
Write-Output "Done. A reboot is required for changes to take effect."
                """.strip()
            ],
        )
        n += 1

    return n


# ── Public check ───────────────────────────────────────────────────────────────

_OC_PREAMBLE = (
    "⚠ OVERCLOCKING RISK WARNING ⚠  "
    "The findings below are ADVISORY ONLY. No changes have been made to your system. "
    "Overclocking can void warranties, cause data loss, system crashes, or permanent "
    "hardware damage. Every chip is different — settings that are stable on one system "
    "may destroy another of the same model. "
    "DO NOT act on any finding here unless you fully understand the risks, have "
    "adequate cooling, and are prepared to stress-test thoroughly after every change."
)


def check_overclock(reporter) -> None:
    """
    Detect overclockable components and provide per-component OC advisory.

    All findings are informational (REVIEW/INFO) except thermal emergencies (HIGH).
    No fix_cmds in this module make OC changes — only MSI mode (a latency fix)
    provides an automated registry command.
    """
    reporter.begin("OVERCLOCKING ADVISORY", _OC_PREAMBLE)
    n = 0

    if _OS == "Windows":
        n += _oc_cpu_windows(reporter)
        n += _oc_gpu_nvidia(reporter)
        n += _oc_ram(reporter)
        n += _oc_msi_mode_windows(reporter)
    elif _OS == "Linux":
        n += _oc_cpu_linux(reporter)
        n += _oc_gpu_nvidia(reporter)
        n += _oc_gpu_amd_linux(reporter)
        n += _oc_ram(reporter)
    elif _OS == "Darwin":
        n += _oc_cpu_macos(reporter)
        n += _oc_gpu_nvidia(reporter)

    if n == 0:
        reporter.ok("No OC advisory items found for this platform/configuration")
    reporter.end(f"{n} OC advisory item(s). All findings are informational — no changes were made.")
