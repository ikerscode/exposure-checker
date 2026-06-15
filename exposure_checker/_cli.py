"""Command-line interface entry point."""

import argparse
import json
import os
import sys

from ._core import _OS, _Reporter, __version__, _DEFAULT_BASELINE, SEVERITY_ORDER, _SMTP_CONFIG_PATH
from .checks.security import (
    audit_ssh, check_tls, scan_trivy, check_firewall, check_listeners,
    check_world_writable, check_suid, check_cron, check_packages,
    check_kernel_hardening, check_sensitive_perms, check_user_accounts,
    check_docker_socket, check_auth_log, check_malware,
    _AV_CLAMAV_PATHS,
)
from .checks.performance import (
    check_startup, check_power_settings, check_gpu_settings,
    check_protection_hardening, check_network_perf,
    check_memory_perf, check_system_resources,
)
from .checks.cleaner import check_system_cleaner
from .checks.benchmark import check_benchmark
from .checks.overclock import check_overclock
from .checks.portscan import resolve_target, run_port_scan
from ._report import (
    _diff_main, _print_diff, _load_report, _save_baseline,
    diff_reports, _compute_score,
)
from ._remediate import _remediate_main
from ._notify import run_headless_scan
from ._schedule import _schedule_main
from ._storage import _PROFILE_MAP, _PROFILE_CHECKS

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "diff":
        _diff_main(sys.argv[2:])
        return

    if len(sys.argv) > 1 and sys.argv[1] == "remediate":
        _remediate_main(sys.argv[2:])
        return

    if len(sys.argv) > 1 and sys.argv[1] == "headless":
        import argparse as _ap
        p = _ap.ArgumentParser(prog="gullwing headless")
        p.add_argument("--tabs", nargs="+",
                       default=["security"],
                       choices=["security", "antivirus", "performance",
                                "protection", "cleaner"])
        p.add_argument("--no-notify", action="store_true")
        a = p.parse_args(sys.argv[2:])
        run_headless_scan(a.tabs, notify=not a.no_notify)
        return

    if len(sys.argv) > 1 and sys.argv[1] == "schedule":
        _schedule_main(sys.argv[2:])
        return

    parser = argparse.ArgumentParser(
        prog="gullwing",
        description="Scan a machine YOU OWN for risky open ports and weak config.")
    parser.add_argument("--version", action="version", version=f"gullwing {__version__}")
    parser.add_argument("target", nargs="?", default="127.0.0.1",
                        help="IP or hostname to scan (default: your own machine).")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Per-port timeout in seconds (default: 1.0).")

    # Local checks
    parser.add_argument("--ssh-audit", action="store_true",
                        help="Audit /etc/ssh/sshd_config for weak settings.")
    parser.add_argument("--ssh-audit-only", action="store_true",
                        help="Run only the SSH audit; skip the port scan.")
    parser.add_argument("--check-firewall", action="store_true",
                        help="Check whether a firewall is active.")
    parser.add_argument("--check-listeners", action="store_true",
                        help="List TCP services bound to non-localhost interfaces.")
    parser.add_argument("--check-world-writable", action="store_true",
                        help="Find world-writable files in standard system directories.")
    parser.add_argument("--check-suid", action="store_true",
                        help="Find SUID/SGID binaries in standard binary paths.")
    parser.add_argument("--check-cron", action="store_true",
                        help="Audit cron jobs for world-writable script paths.")
    parser.add_argument("--check-packages", action="store_true",
                        help="Check for pending OS package updates (apt/dnf/yum).")
    parser.add_argument("--check-kernel", action="store_true",
                        help="Audit sysctl kernel hardening parameters.")
    parser.add_argument("--check-sensitive-perms", action="store_true",
                        help="Check permissions on /etc/shadow, /etc/sudoers, SSH host keys, etc.")
    parser.add_argument("--check-user-accounts", action="store_true",
                        help="Check for extra UID-0 accounts and empty passwords.")
    parser.add_argument("--check-docker", action="store_true",
                        help="Check Docker socket permissions.")
    parser.add_argument("--check-auth", action="store_true",
                        help="Scan auth log for SSH brute-force and sudo failures "
                             "(requires read access to /var/log/auth.log).")
    parser.add_argument("--check-malware", action="store_true",
                        help="Malware scan: ClamAV signatures (if installed) + heuristic "
                             "indicators (temp executables, suspicious processes, rootkit "
                             "markers, known-bad script patterns).")
    parser.add_argument("--malware-paths", nargs="+", metavar="PATH",
                        help="Override default paths for the ClamAV scan "
                             f"(default: {', '.join(_AV_CLAMAV_PATHS)}).")
    parser.add_argument("--check-startup", action="store_true",
                        help="Audit programs configured to launch at boot/login.")
    parser.add_argument("--check-cleaner", action="store_true",
                        help="Scan for reclaimable disk space (caches, temp junk, debris).")
    parser.add_argument("--check-power", action="store_true",
                        help="Audit power settings that affect gaming performance and latency.")
    parser.add_argument("--check-gpu", action="store_true",
                        help="Audit GPU, game capture, and driver-related gaming settings.")
    parser.add_argument("--check-protection", action="store_true",
                        help="Audit extra local protection controls for ransomware and remote access.")
    parser.add_argument("--check-network-perf", action="store_true",
                        help="Audit network stack settings that affect gaming latency and throughput.")
    parser.add_argument("--check-memory-perf", action="store_true",
                        help="Check RAM usage and memory performance settings.")
    parser.add_argument("--check-system-resources", action="store_true",
                        help="Check CPU, disk, and GPU utilisation for resource bottlenecks.")
    parser.add_argument("--benchmark", action="store_true",
                        help="Run a ~10 s CPU/memory/disk benchmark and report tier ratings (S–F).")
    parser.add_argument("--check-overclock", action="store_true",
                        help="Advisory-only OC report: CPU boost, GPU clocks/thermals, RAM XMP, "
                             "MSI mode. No changes are made. Includes risk warnings.")
    parser.add_argument("--gamer-audit", action="store_true",
                        help="Run the local gamer optimization suite: startup, power, GPU, "
                             "cleaner, and extra protection checks.")
    parser.add_argument("--full-audit", action="store_true",
                        help="Run all local checks (port scan + SSH + firewall + "
                             "listeners + world-writable + SUID + cron + packages + "
                             "kernel + sensitive-perms + user-accounts + docker + "
                             "auth + malware + cleaner + startup + power + GPU + "
                             "protection + network perf + memory + system resources).")

    # Remote / tool-dependent checks
    parser.add_argument("--tls-check", metavar="HOST[:PORT]",
                        help="Check TLS certificate expiry (default port: 443).")
    parser.add_argument("--trivy-scan", nargs="?", const="ALL", metavar="IMAGE[:TAG]",
                        help="CVE-scan local Docker images with Trivy. "
                             "Omit IMAGE to scan all local images.")

    # Output format
    parser.add_argument("--json", action="store_true",
                        help="Emit findings as JSON instead of human-readable text.")
    parser.add_argument("--output", metavar="FILE",
                        help="Write the full report to FILE (.json or .html auto-detected).")
    parser.add_argument("--fail-on", metavar="SEVERITY",
                        choices=["critical", "high", "medium", "review", "info"],
                        type=str.lower,
                        help="Exit with status 1 if any finding is at or above SEVERITY "
                             "(or any NEW finding when used with --diff-baseline).")
    parser.add_argument("--profile",
                        choices=list(_PROFILE_MAP),
                        metavar="PROFILE",
                        help="Check compliance against a named profile and exit 1 if any "
                             "required control fails.  Choices: "
                             + ", ".join(_PROFILE_MAP) + ".  "
                             "Required checks for the profile are enabled automatically.")
    parser.add_argument("--email", metavar="ADDRESS",
                        help="Email scan summary to ADDRESS after the scan completes. "
                             f"SMTP credentials must be set in {_SMTP_CONFIG_PATH}.")

    # Baseline
    parser.add_argument("--baseline-file", metavar="FILE", default=_DEFAULT_BASELINE,
                        help=f"Path to the baseline file (default: {_DEFAULT_BASELINE}).")
    parser.add_argument("--save-baseline", action="store_true",
                        help="Save this scan as the new baseline.")
    parser.add_argument("--diff-baseline", action="store_true",
                        help="Diff this scan against the saved baseline and show changes.")

    args = parser.parse_args()

    # Auto-enable required checks for the chosen compliance profile
    if args.profile:
        for flag in _PROFILE_CHECKS.get(args.profile, []):
            if not getattr(args, flag, False):
                setattr(args, flag, True)

    reporter = _Reporter(json_mode=args.json)

    if not args.json:
        print("=" * 66)
        print("  GULLWING")
        print("  !  Only scan systems you own or are authorised to test.")
        print("=" * 66)

    if sys.platform == "win32":
        try:
            import ctypes as _ctypes
            _is_admin = bool(_ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            _is_admin = False
    else:
        _is_admin = (os.geteuid() == 0)

    _admin_flags = [
        "ssh_audit", "ssh_audit_only", "check_firewall", "check_listeners",
        "check_world_writable", "check_suid", "check_cron", "check_packages",
        "check_kernel", "check_sensitive_perms", "check_user_accounts",
        "check_docker", "check_auth", "check_malware", "check_startup",
        "check_cleaner", "check_power", "check_gpu", "check_protection",
        "check_network_perf", "check_memory_perf", "check_system_resources",
        "benchmark", "check_overclock",
        "full_audit", "gamer_audit",
    ]
    _needs_admin = any(getattr(args, flag, False) for flag in _admin_flags)

    if not _is_admin and _needs_admin:
        msg = (
            "[!] Administrator privileges required for a complete scan.\n"
            "    Some checks (auth log, kernel params, file permissions) will\n"
            "    be skipped or return incomplete results without them.\n"
        )
        if sys.platform == "win32":
            msg += "    Re-run in an elevated (Administrator) terminal."
        else:
            msg += f"    Re-run with: sudo {' '.join(sys.argv)}"
        if args.json:
            import json as _json
            print(_json.dumps({"error": "administrator_required", "detail": msg.strip()}))
        else:
            print(msg, file=sys.stderr)
        sys.exit(1)

    if not args.ssh_audit_only:
        ip, display = resolve_target(args.target)
        run_port_scan(reporter, ip, display, args.timeout)

    if args.ssh_audit or args.ssh_audit_only or args.full_audit:
        audit_ssh(reporter)

    if args.check_firewall or args.full_audit:
        check_firewall(reporter)

    if args.check_listeners or args.full_audit:
        check_listeners(reporter)

    if args.check_world_writable or args.full_audit:
        check_world_writable(reporter)

    if args.check_suid or args.full_audit:
        check_suid(reporter)

    if args.check_cron or args.full_audit:
        check_cron(reporter)

    if args.check_packages or args.full_audit:
        check_packages(reporter)

    if args.check_kernel or args.full_audit:
        check_kernel_hardening(reporter)

    if args.check_sensitive_perms or args.full_audit:
        check_sensitive_perms(reporter)

    if args.check_user_accounts or args.full_audit:
        check_user_accounts(reporter)

    if args.check_docker or args.full_audit:
        check_docker_socket(reporter)

    if args.check_auth or args.full_audit:
        check_auth_log(reporter)

    if args.check_malware or args.full_audit:
        check_malware(reporter, clamav_paths=args.malware_paths or None)

    if args.check_startup or args.full_audit or args.gamer_audit:
        check_startup(reporter)

    if args.check_cleaner or args.full_audit or args.gamer_audit:
        check_system_cleaner(reporter)

    if args.check_power or args.full_audit or args.gamer_audit:
        check_power_settings(reporter)

    if args.check_gpu or args.full_audit or args.gamer_audit:
        check_gpu_settings(reporter)

    if args.check_protection or args.full_audit or args.gamer_audit:
        check_protection_hardening(reporter)

    if args.check_network_perf or args.full_audit or args.gamer_audit:
        check_network_perf(reporter)

    if args.check_memory_perf or args.full_audit or args.gamer_audit:
        check_memory_perf(reporter)

    if args.check_system_resources or args.full_audit or args.gamer_audit:
        check_system_resources(reporter)

    if args.benchmark or args.gamer_audit:
        check_benchmark(reporter)

    if args.check_overclock:
        check_overclock(reporter)

    if args.tls_check:
        check_tls(reporter, args.tls_check)

    if args.trivy_scan is not None:
        scan_trivy(reporter, args.trivy_scan)

    score, grade = _compute_score(reporter._data)
    reporter._data["score"] = score
    reporter._data["grade"] = grade
    if not args.json:
        bar = "█" * (score // 5) + "░" * (20 - score // 5)
        counts: dict[str, int] = {}
        for chk in reporter._data.get("checks", []):
            for f in chk.get("findings", []):
                s = f.get("severity", "")
                counts[s] = counts.get(s, 0) + 1
        parts = [f"{counts[s]} {s}" for s in ("CRITICAL", "HIGH", "MEDIUM", "REVIEW", "INFO") if counts.get(s)]
        summary = "  " + " · ".join(parts) if parts else "  No findings"
        print(f"\n  Risk Score  {score}/100  [{bar}]  Grade: {grade}")
        print(summary)

    _profile_failed = False
    if args.profile:
        profile_name = _PROFILE_MAP[args.profile]
        required     = _COMPLIANCE_REQUIRED.get(profile_name, {})
        sev_rank     = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "REVIEW": 1, "INFO": 0}
        all_findings = [f for chk in reporter._data.get("checks", [])
                        for f in chk.get("findings", [])]
        failing: dict = {}
        for f in all_findings:
            chk_name = f.get("check", "").lower()
            sev      = f.get("severity", "INFO")
            for req_key, min_sev in required.items():
                if (req_key in chk_name
                        and sev_rank.get(sev, 0) >= sev_rank.get(min_sev, 0)
                        and req_key not in failing):
                    failing[req_key] = f.get("label", sev)
        n_pass  = len(required) - len(failing)
        n_total = len(required)
        pct     = int(100 * n_pass / n_total) if n_total else 100
        result  = "PASS" if pct == 100 else "FAIL"
        reporter._data["compliance"] = {
            "profile": profile_name, "passing": n_pass,
            "total": n_total, "pct": pct, "result": result,
            "failing": failing,
        }
        if not args.json:
            col_w = max((len(k) for k in required), default=10) + 2
            bar_p = "█" * (pct // 5) + "░" * (20 - pct // 5)
            print(f"\n  ─── {profile_name} " + "─" * max(0, 44 - len(profile_name)))
            for key, min_sev in required.items():
                status = "FAIL" if key in failing else "PASS"
                detail = f"  ← {failing[key]}" if key in failing else ""
                print(f"  {key:<{col_w}} {status}{detail}")
            print(f"\n  Compliance  {n_pass}/{n_total}  [{bar_p}]  {pct}%  {result}")
        _profile_failed = pct < 100

    if args.output:
        err = reporter.write_to(args.output)
        if err:
            print(f"[!] Could not write report to {args.output}: {err}.", file=sys.stderr)
        elif not args.json:
            print(f"[*] Report saved → {args.output}")

    if args.email:
        try:
            _send_notification(args.email, reporter._data)
            if not args.json:
                print(f"[*] Notification sent → {args.email}")
        except Exception as exc:
            print(f"[!] Email failed: {exc}", file=sys.stderr)

    if args.diff_baseline:
        b_data, err = _load_report(args.baseline_file)
        if err:
            print(
                f"[!] --diff-baseline: {err}. Run with --save-baseline first.",
                file=sys.stderr,
            )
        else:
            diff = diff_reports(b_data, reporter._data)
            if args.json:
                print(json.dumps({
                    "before": {
                        "file": args.baseline_file,
                        "timestamp": b_data.get("timestamp"),
                    },
                    "after": {
                        "file": "(current scan)",
                        "timestamp": reporter._data.get("timestamp"),
                    },
                    "new": [
                        {"check": c, "label": l, "severity": s}
                        for c, l, s in diff["new"]
                    ],
                    "resolved": [
                        {"check": c, "label": l, "severity": s}
                        for c, l, s in diff["resolved"]
                    ],
                    "changed": [
                        {"check": c, "label": l, "before": bv, "after": av}
                        for c, l, bv, av in diff["changed"]
                    ],
                }, indent=2))
            else:
                _print_diff(
                    args.baseline_file, "(current scan)",
                    b_data, reporter._data, diff,
                )
            if args.fail_on:
                threshold = SEVERITY_ORDER.get(args.fail_on.upper(), 9)
                triggered = [
                    (c, l, s) for c, l, s in diff["new"]
                    if SEVERITY_ORDER.get(s, 9) <= threshold
                ]
                if triggered:
                    if not args.json:
                        print(
                            f"\n[!] --fail-on {args.fail_on}: "
                            f"{len(triggered)} new finding(s) at or above "
                            f"{args.fail_on.upper()}."
                        )
                    sys.exit(1)
    else:
        reporter.dump_json()
        if args.fail_on:
            triggered = reporter.findings_at_or_above(args.fail_on)
            if triggered:
                if not args.json:
                    print(
                        f"\n[!] --fail-on {args.fail_on}: "
                        f"{len(triggered)} finding(s) at or above "
                        f"{args.fail_on.upper()}."
                    )
                sys.exit(1)

    if args.save_baseline:
        err = _save_baseline(args.baseline_file, reporter._data)
        if err:
            print(
                f"[!] Could not save baseline to {args.baseline_file}: {err}.",
                file=sys.stderr,
            )
        elif not args.json:
            print(f"\n[*] Baseline saved to {args.baseline_file}")

    if _profile_failed:
        if not args.json:
            n_fail = len(reporter._data.get("compliance", {}).get("failing", {}))
            print(
                f"\n[!] --profile {args.profile}: "
                f"{n_fail} required control(s) failing."
            )
        sys.exit(1)


if __name__ == "__main__":
    main()
