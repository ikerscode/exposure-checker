"""
System performance benchmark — CPU, memory, and disk.

Pure standard-library implementation; no external tools required.
Results are reproducible and comparable across runs stored in scan history.

Tier thresholds calibrated against typical gaming rigs (2020–2025):
  S — top-tier / enthusiast
  A — excellent, no bottleneck
  B — good, competitive gaming viable
  C — average, may bottleneck in demanding titles
  D — below average, noticeable bottleneck
  F — poor, significant performance limiter
"""

import hashlib
import math
import os
import tempfile
import time

from .._core import _OS, _truncate


# ── CPU benchmarks ─────────────────────────────────────────────────────────────

def _bench_cpu_hash(duration: float = 3.0) -> float:
    """SHA-256 throughput in MB/s over a 64 KB block (stresses L2/L3 cache)."""
    chunk = b"\xAB" * 65536
    deadline = time.monotonic() + duration
    n = 0
    while time.monotonic() < deadline:
        hashlib.sha256(chunk).digest()
        n += 1
    return round((n * 65536) / (1024 * 1024) / duration, 1)


def _bench_cpu_float(duration: float = 2.0) -> float:
    """Trig-heavy float loop in Mop/s — proxy for physics / AI workloads."""
    deadline = time.monotonic() + duration
    n = 0
    x = 1.0
    while time.monotonic() < deadline:
        x = math.sqrt(math.sin(x) * math.cos(x) + 1.0001)
        n += 1
    return round(n / 1_000_000 / duration, 2)


# ── Memory benchmark ───────────────────────────────────────────────────────────

def _bench_memory(size_mb: int = 256) -> dict:
    """Sequential fill + read of a large buffer. Returns GB/s."""
    size = size_mb * 1024 * 1024
    fill = b"\xFF" * 4096

    t0 = time.monotonic()
    buf = bytearray(size)
    for i in range(0, size, 4096):
        buf[i : i + 4096] = fill
    write_s = max(time.monotonic() - t0, 1e-9)

    t0 = time.monotonic()
    _ = bytes(memoryview(buf))
    read_s = max(time.monotonic() - t0, 1e-9)

    gb = size / 1024 ** 3
    return {
        "write_gb_s": round(gb / write_s, 2),
        "read_gb_s":  round(gb / read_s,  2),
    }


# ── Disk benchmark ─────────────────────────────────────────────────────────────

def _bench_disk(size_mb: int = 128) -> dict:
    """Sequential write (fsync) + read of a temp file. Returns MB/s."""
    size  = size_mb * 1024 * 1024
    chunk = b"\x00" * 65536
    path  = None
    try:
        fd, path = tempfile.mkstemp(prefix="ec_bench_")
        os.close(fd)

        t0 = time.monotonic()
        with open(path, "wb") as f:
            written = 0
            while written < size:
                f.write(chunk)
                written += len(chunk)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        write_s = max(time.monotonic() - t0, 1e-9)

        t0 = time.monotonic()
        with open(path, "rb") as f:
            while f.read(65536):
                pass
        read_s = max(time.monotonic() - t0, 1e-9)

    finally:
        if path and os.path.exists(path):
            try:
                os.unlink(path)
            except OSError:
                pass

    mb = size / 1024 ** 2
    return {
        "write_mb_s": round(mb / write_s, 1),
        "read_mb_s":  round(mb / read_s,  1),
    }


# ── Tier rating ────────────────────────────────────────────────────────────────

def _tier(value: float, thresholds: list) -> str:
    for minimum, letter in thresholds:
        if value >= minimum:
            return letter
    return "F"


_CPU_HASH_TIERS  = [(4000, "S"), (2500, "A"), (1500, "B"), (750,  "C"), (350,  "D")]
_CPU_FLOAT_TIERS = [(80,   "S"), (50,   "A"), (30,   "B"), (15,   "C"), (7,    "D")]
_MEM_READ_TIERS  = [(50,   "S"), (30,   "A"), (18,   "B"), (8,    "C"), (3,    "D")]
_DISK_READ_TIERS = [(5000, "S"), (2500, "A"), (1000, "B"), (300,  "C"), (80,   "D")]

_TIER_SEV = {
    "S": "INFO", "A": "INFO", "B": "INFO",
    "C": "REVIEW", "D": "MEDIUM", "F": "HIGH",
}

_TIER_LABEL = {
    "S": "Exceptional", "A": "Excellent", "B": "Good",
    "C": "Average", "D": "Below average", "F": "Poor",
}

_TIER_ORDER = ["S", "A", "B", "C", "D", "F"]


def _composite(tiers: list) -> str:
    return max(tiers, key=lambda t: _TIER_ORDER.index(t))


# ── Public check ───────────────────────────────────────────────────────────────

def check_benchmark(reporter) -> None:
    """
    Run a ~10-second CPU/memory/disk benchmark and report tier ratings.

    Tiers correlate to gaming impact:
      S/A — no bottleneck for current-gen titles
      B   — fine for most games; may limit a few CPU-heavy titles
      C   — noticeable in demanding scenes; consider upgrade path
      D/F — significant bottleneck; will limit frame rate / load times
    """
    reporter.begin("BENCHMARK", "CPU · Memory · Disk — hardware performance tiers")

    # ── CPU hash throughput ────────────────────────────────────────────────────
    hash_mb_s  = _bench_cpu_hash(3.0)
    hash_tier  = _tier(hash_mb_s, _CPU_HASH_TIERS)
    reporter.finding(
        _TIER_SEV[hash_tier],
        f"CPU hash throughput: {hash_tier} ({_TIER_LABEL[hash_tier]}) — {hash_mb_s:,.1f} MB/s",
        "SHA-256 throughput over a 64 KB block. Correlates with game-engine asset "
        "hashing, pak-file decompression, and anti-cheat overhead. "
        "Reference points: i9-13900K ≈ 4 800 MB/s · i7-12700 ≈ 3 200 MB/s · "
        "i5-10600K ≈ 1 600 MB/s · i5-8400 ≈ 900 MB/s.",
        "Tier A/S: no action needed. Lower tiers: ensure no background CPU load, "
        "power plan is High Performance, and Turbo Boost / Precision Boost is enabled.",
    )

    # ── CPU float throughput ───────────────────────────────────────────────────
    float_mops = _bench_cpu_float(2.0)
    float_tier = _tier(float_mops, _CPU_FLOAT_TIERS)
    reporter.finding(
        _TIER_SEV[float_tier],
        f"CPU float throughput: {float_tier} ({_TIER_LABEL[float_tier]}) — {float_mops:,.2f} Mop/s",
        "Trig-heavy floating-point loop — proxy for physics simulation, AI pathfinding, "
        "and procedural-generation workloads common in modern open-world games.",
        "Tier A/S: no action needed. Lower tiers may indicate thermal throttling — "
        "check CPU temperatures and fan curves.",
    )

    # ── Memory bandwidth ───────────────────────────────────────────────────────
    mem       = _bench_memory(256)
    mem_tier  = _tier(mem["read_gb_s"], _MEM_READ_TIERS)
    reporter.finding(
        _TIER_SEV[mem_tier],
        (f"Memory bandwidth: {mem_tier} ({_TIER_LABEL[mem_tier]}) — "
         f"{mem['read_gb_s']:.2f} GB/s read / {mem['write_gb_s']:.2f} GB/s write"),
        "Sequential memory bandwidth. Low bandwidth causes GPU stalls when the CPU "
        "cannot feed data fast enough — visible as frame-time spikes in CPU-bound "
        "games. Reference: DDR5-6000 dual-ch ≈ 80 GB/s · DDR4-3600 dual-ch ≈ 45 GB/s "
        "· DDR4-2133 single-ch ≈ 14 GB/s.",
        "Tier A/S: no action. For lower tiers: enable XMP/EXPO in BIOS for rated "
        "RAM speed; ensure two sticks are installed in matched slots (dual-channel).",
    )

    # ── Disk throughput ────────────────────────────────────────────────────────
    disk      = _bench_disk(128)
    disk_tier = _tier(disk["read_mb_s"], _DISK_READ_TIERS)
    reporter.finding(
        _TIER_SEV[disk_tier],
        (f"Disk (sequential): {disk_tier} ({_TIER_LABEL[disk_tier]}) — "
         f"{disk['read_mb_s']:,.0f} MB/s read / {disk['write_mb_s']:,.0f} MB/s write"),
        "Sequential storage throughput. Directly affects game load times, open-world "
        "asset streaming, and shader-compilation speed on first launch. "
        "Reference: PCIe 5.0 NVMe ≈ 12 000 MB/s · PCIe 4.0 NVMe ≈ 7 000 MB/s · "
        "PCIe 3.0 NVMe ≈ 3 500 MB/s · SATA SSD ≈ 550 MB/s · HDD ≈ 120 MB/s.",
        "Tier A/S: no action. For C/D/F: move game installs to an NVMe SSD. "
        "HDDs are a major bottleneck for modern open-world titles with large streaming budgets.",
    )

    composite = _composite([hash_tier, float_tier, mem_tier, disk_tier])
    reporter.end(
        f"Benchmark complete — composite tier {composite} "
        f"(CPU hash {hash_tier} · float {float_tier} · RAM {mem_tier} · Disk {disk_tier})"
    )
