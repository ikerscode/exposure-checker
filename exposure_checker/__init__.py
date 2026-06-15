"""
Gullwing — local security, performance, and cleaner scanner.

This package re-exports every public symbol so that existing code using
``import exposure_checker as ec`` continues to work unchanged.
"""

import os
import shutil
import subprocess

from ._core import (
    __version__,
    _OS,
    _ps,
    _ps_quote,
    _shell_quote,
    _truncate,
    _self_invocation,
    _NO_WINDOW,
    RISKY_PORTS,
    SPECIAL,
    SEVERITY_ORDER,
    _SCORE_WEIGHTS,
    _DEFAULT_BASELINE,
    _SMTP_CONFIG_PATH,
    _SCHEDULE_FILE,
    _Reporter,
    _CRYPTO_OK,
)

# ── Security checks ────────────────────────────────────────────────────────────
from .checks.security import (
    audit_ssh,
    check_tls,
    scan_trivy,
    check_firewall,
    check_listeners,
    check_world_writable,
    check_suid,
    check_cron,
    check_kernel_hardening,
    check_sensitive_perms,
    check_user_accounts,
    check_docker_socket,
    check_auth_log,
    check_malware,
    check_packages,
    # private helpers exposed for tests
    _parse_sshd_config,
    _parse_grace_time,
    _parse_tls_target,
    _validate_image_name,
    _trivy_scan_one,
    _check_firewall_macos,
    _parse_ss_addr,
    _CRON_FILES,
    _CRON_DIRS,
    _CRON_ROOT_SPOOL,
    _read_sysctl,
    _win_third_party_av,
    _check_malware_windows,
    _AV_TEMP_DIRS,
    _AV_SCRIPT_DIRS,
    _MACHO_MAGICS,
    _av_check_temp_executables,
    _av_check_suspicious_procs,
    _av_check_ld_preload,
    _av_run_clamav,
    _av_scan_scripts,
    _check_gatekeeper_macos,
    _check_launchd_persistence_macos,
    _parse_winget_upgrade_count,
    _parse_apt_upgradeable,
    _parse_dnf_check_update,
)

# ── Performance & protection checks ───────────────────────────────────────────
from .checks.performance import (
    check_startup,
    check_power_settings,
    check_gpu_settings,
    check_network_perf,
    check_memory_perf,
    check_system_resources,
    check_protection_hardening,
    # private helpers exposed for tests
    _json_array,
    _mp_value_disabled,
    _check_startup_linux,
)

# ── Cleaner checks ─────────────────────────────────────────────────────────────
from .checks.cleaner import (
    check_system_cleaner,
    _browser_cache_dirs,
    _dev_cache_dirs,
    _cleaner_common_caches,
)

# ── Benchmark ─────────────────────────────────────────────────────────────────
from .checks.benchmark import (
    check_benchmark,
    _bench_cpu_hash,
    _bench_cpu_float,
    _bench_memory,
    _bench_disk,
)

# ── Overclocking advisory ──────────────────────────────────────────────────────
from .checks.overclock import (
    check_overclock,
    _oc_msi_mode_windows,
)

# ── Port scanner ───────────────────────────────────────────────────────────────
from .checks.portscan import (
    resolve_target,
    check_port,
    scan,
    describe,
    run_port_scan,
)

# ── Reporting ──────────────────────────────────────────────────────────────────
from ._report import (
    _compute_score,
    _render_html,
    diff_reports,
    _save_baseline,
    _load_report,
    _print_diff,
    _diff_main,
    generate_pdf_report,
)

# ── Persistent storage ─────────────────────────────────────────────────────────
from ._storage import (
    save_scan_history,
    load_scan_history,
    _risk_key,
    load_accepted_risks,
    save_accepted_risk,
    remove_accepted_risk,
    is_accepted_risk,
    COMPLIANCE_PROFILES,
    compliance_score,
    take_snapshot,
    save_snapshot,
    list_snapshots,
    delete_snapshot,
    restore_snapshot,
)

# ── Headless scan / remote scan ────────────────────────────────────────────────
from ._notify import (
    run_headless_scan,
    run_remote_scan,
)

# ── Fix runner ─────────────────────────────────────────────────────────────────
from . import _remediate
from ._remediate import (
    _run_fix_cmd,
    _collect_fixable,
    _remediate_main,
)

# ── CLI entry point ────────────────────────────────────────────────────────────
from ._cli import main

# ── Schedule management ────────────────────────────────────────────────────────
from ._schedule import (
    load_schedule,
    save_schedule,
    install_schedule,
    _read_ec_cron_jobs,
    _schedule_main,
)
