#!/usr/bin/env python3
"""
Exposure Checker - scan a machine YOU OWN for risky open ports.

USAGE:
    python exposure_checker.py                 # scans your own machine (127.0.0.1)
    python exposure_checker.py 192.168.1.50    # scans a host on your LAN you own

WARNING: Only scan systems you own or have WRITTEN permission to test.
         Scanning machines you don't control is illegal in most places.
"""

import argparse
import concurrent.futures
import ipaddress
import socket
import sys

# port -> (service, severity, why it matters, how to fix)
RISKY_PORTS = {
    21:    ("FTP", "HIGH", "File transfer, usually unencrypted - credentials sent in clear text.",
            "Disable FTP; use SFTP/SCP over SSH instead."),
    23:    ("Telnet", "CRITICAL", "Remote login with NO encryption - passwords travel in plain text.",
            "Disable telnet entirely and use SSH."),
    25:    ("SMTP", "MEDIUM", "Mail server. If open to the internet it can be abused as an open relay.",
            "Restrict to known hosts / require auth, or firewall it."),
    53:    ("DNS", "MEDIUM", "DNS server. An open resolver can be abused in amplification attacks.",
            "Disable public recursion or firewall to trusted clients."),
    80:    ("HTTP", "INFO", "An (unencrypted) web service is running. Fine if intended.",
            "Serve over HTTPS; make sure it isn't an unprotected admin panel."),
    110:   ("POP3", "MEDIUM", "Legacy mail retrieval, often plaintext.",
            "Use encrypted POP3S/IMAPS, or disable."),
    135:   ("MS-RPC", "HIGH", "Windows RPC - a frequent target for remote exploits.",
            "Never expose to the internet; firewall to the local network only."),
    139:   ("NetBIOS", "HIGH", "Legacy Windows sharing - leaks info, historically wormable.",
            "Disable NetBIOS over TCP/IP; firewall it."),
    445:   ("SMB", "HIGH", "Windows file sharing - the EternalBlue/WannaCry port.",
            "Block 445 at the firewall; never expose SMB to the internet."),
    1433:  ("MS-SQL", "HIGH", "Microsoft SQL Server exposed to the network.",
            "Bind to localhost or firewall to app servers; require strong auth."),
    2375:  ("Docker API (plain)", "CRITICAL", "Unencrypted, UNAUTHENTICATED Docker API = full root on the host.",
            "Never expose this. Use the local socket; if remote, use TLS (2376) with client certs."),
    2376:  ("Docker API (TLS)", "HIGH", "Docker API over TLS - still remote root if certs leak.",
            "Restrict to trusted clients; protect the client certificates."),
    3000:  ("Dev/app panel (3000)", "MEDIUM", "Common dev server / dashboard (Grafana, Node apps).",
            "Ensure it requires auth and isn't reachable beyond localhost/LAN."),
    3306:  ("MySQL/MariaDB", "HIGH", "Database exposed to the network.",
            "Bind to 127.0.0.1 or firewall to app servers; require strong auth."),
    3389:  ("RDP", "HIGH", "Windows Remote Desktop - a top brute-force / ransomware entry point.",
            "Don't expose to the internet; use a VPN, enable NLA + strong passwords + MFA."),
    5000:  ("Dev/app panel (5000)", "MEDIUM", "Common dev server (Flask etc.).",
            "Make sure it isn't a debug server exposed in production."),
    5432:  ("PostgreSQL", "HIGH", "Database exposed to the network.",
            "Bind to 127.0.0.1 or firewall to app servers; require strong auth."),
    5900:  ("VNC", "HIGH", "Remote desktop, frequently weak or no authentication.",
            "Tunnel over SSH/VPN; never expose VNC directly; set a strong password."),
    6379:  ("Redis", "CRITICAL", "Redis often has NO auth by default - open means data theft / RCE.",
            "Bind to 127.0.0.1, set 'requirepass', and firewall it."),
    8080:  ("HTTP-alt / panel (8080)", "MEDIUM", "Common alternate web / admin panel port.",
            "Require auth; don't expose admin interfaces to the network."),
    8081:  ("Admin panel (8081)", "MEDIUM", "Common admin/management interface port.",
            "Require auth; restrict to localhost/LAN."),
    9000:  ("Portainer / panel (9000)", "MEDIUM", "Often Portainer (Docker management) or other dashboards.",
            "Require strong auth; don't expose container management to the network."),
    9090:  ("Prometheus / panel (9090)", "MEDIUM", "Often Prometheus or an admin dashboard - frequently no auth.",
            "Put behind auth / a reverse proxy; restrict to localhost/LAN."),
    9200:  ("Elasticsearch", "CRITICAL", "Elasticsearch often has no auth by default - open = full data access.",
            "Enable security, bind to localhost, and firewall it."),
    11211: ("Memcached", "HIGH", "No auth by default; abused for huge amplification attacks.",
            "Bind to 127.0.0.1 and firewall it."),
    27017: ("MongoDB", "CRITICAL", "MongoDB historically shipped with no auth - open = full data access.",
            "Enable auth, bind to 127.0.0.1, and firewall it."),
}

# Ports that are 'take a closer look' rather than inherently bad
SPECIAL = {
    22:  ("SSH", "REVIEW", "SSH is fine IF it's key-only. Password auth invites brute-forcing.",
          "Set 'PasswordAuthentication no', use keys, consider fail2ban."),
    443: ("HTTPS", "INFO", "Encrypted web service - good. Just confirm it isn't an exposed admin panel.",
          "Keep TLS current; protect any admin UI behind auth."),
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "REVIEW": 3, "INFO": 4}


def resolve_target(target):
    """Validate/resolve the target. Returns (ip, display) or exits cleanly."""
    try:
        ip = str(ipaddress.ip_address(target))   # already an IP?
        return ip, target
    except ValueError:
        pass
    try:
        ip = socket.gethostbyname(target)        # otherwise resolve hostname
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


def main():
    parser = argparse.ArgumentParser(
        description="Scan a machine YOU OWN for risky open ports.")
    parser.add_argument("target", nargs="?", default="127.0.0.1",
                        help="IP or hostname to scan (default: your own machine).")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Per-port timeout in seconds (default: 1.0).")
    args = parser.parse_args()

    print("=" * 66)
    print("  EXPOSURE CHECKER")
    print("  !  Only scan systems you own or are authorised to test.")
    print("=" * 66)

    ip, display = resolve_target(args.target)
    all_ports = sorted(set(RISKY_PORTS) | set(SPECIAL))
    print(f"\n[*] Target : {display}")
    print(f"[*] Checking {len(all_ports)} commonly-risky ports...\n")

    open_ports = scan(ip, all_ports, args.timeout)

    if not open_ports:
        print("[+] No risky ports found open. Nice - small attack surface.\n")
        return

    findings = sorted((((p,) + describe(p)) for p in open_ports),
                      key=lambda f: SEVERITY_ORDER.get(f[2], 9))

    print(f"[!] {len(open_ports)} open port(s) found:\n")
    for port, service, severity, why, fix in findings:
        print(f"  [{severity}] port {port} - {service}")
        print(f"      why : {why}")
        print(f"      fix : {fix}\n")

    crit = sum(1 for f in findings if f[2] == "CRITICAL")
    high = sum(1 for f in findings if f[2] == "HIGH")
    print("-" * 66)
    print(f"  Summary: {crit} critical, {high} high-risk open. Review the items above.")
    print("-" * 66)


if __name__ == "__main__":
    main()
