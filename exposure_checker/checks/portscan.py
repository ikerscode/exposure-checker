"""Active port scanner: TCP connect scan with risk-database lookup."""

import concurrent.futures
import ipaddress
import json
import os
import shutil
import socket
import sys

from .._core import (
    _OS, _ps, _ps_quote, _shell_quote, _truncate,
    RISKY_PORTS, SPECIAL, SEVERITY_ORDER,
    _CRYPTO_OK, _cx509,
    _NO_WINDOW,
)

# ── Port scan ──────────────────────────────────────────────────────────────────

def resolve_target(target):
    """Validate/resolve the target. Returns (ip, display) or exits cleanly."""
    try:
        ip = str(ipaddress.ip_address(target))
        return ip, target
    except ValueError:
        pass
    try:
        ip = socket.gethostbyname(target)
        return ip, f"{target} ({ip})"
    except socket.gaierror:
        sys.exit(f"[!] Could not resolve '{target}'. Use a valid IP or hostname.")


def check_port(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return port if s.connect_ex((ip, port)) == 0 else None
    except OSError:
        return None
    finally:
        s.close()


def scan(ip, ports, timeout, workers=100):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(check_port, ip, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            if (res := fut.result()) is not None:
                open_ports.append(res)
    return sorted(open_ports)


def describe(port):
    if port in RISKY_PORTS:
        return RISKY_PORTS[port]
    if port in SPECIAL:
        return SPECIAL[port]
    return (f"Port {port}", "INFO", "Open port (not in the risk database).",
            "Confirm this service is intended and protected.")


def _port_fix_cmds(port: int, severity: str) -> list:
    """Return firewall block commands for an exposed port.

    INFO and REVIEW ports are advisory-only — no automated fix is appropriate.
    For actionable severities we block the port at the OS firewall so the
    exposure is closed immediately, independent of whatever service owns it.
    """
    if severity in ("INFO", "REVIEW"):
        return []
    p = str(port)
    if _OS == "Windows":
        return [
            f'netsh advfirewall firewall add rule '
            f'name="Block port {p} (exposure-checker)" '
            f'dir=in action=block protocol=TCP localport={p}'
        ]
    if _OS == "Darwin":
        return [
            f'echo "block in proto tcp from any to any port {p}"'
            f' >> /etc/pf.conf',
            "pfctl -ef /etc/pf.conf",
        ]
    # Linux — ufw preferred; fall back to iptables
    if shutil.which("ufw"):
        return [f"ufw deny {p}/tcp"]
    return [f"iptables -A INPUT -p tcp --dport {p} -j DROP"]


def run_port_scan(reporter, ip, display, timeout):
    reporter._data.setdefault("target", display)
    reporter.begin("PORT SCAN", f"Target : {display}")
    all_ports = sorted(set(RISKY_PORTS) | set(SPECIAL))
    reporter.info(f"Checking {len(all_ports)} commonly-risky ports...")
    if not reporter.json_mode:
        print()

    open_ports = scan(ip, all_ports, timeout)

    if not open_ports:
        reporter.ok("No risky ports found open — small attack surface")
        return

    findings = sorted(
        ((p,) + describe(p) for p in open_ports),
        key=lambda f: SEVERITY_ORDER.get(f[2], 9),
    )
    if not reporter.json_mode:
        print(f"[!] {len(open_ports)} open port(s) found:")
    for port, service, severity, why, fix in findings:
        reporter.finding(severity, f"port {port} - {service}", why, fix,
                         port=port, service=service,
                         fix_cmds=_port_fix_cmds(port, severity))

    crit = sum(1 for f in findings if f[2] == "CRITICAL")
    high = sum(1 for f in findings if f[2] == "HIGH")
    reporter.end(f"{crit} critical, {high} high-risk open. Review above.")


