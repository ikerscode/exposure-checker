# Exposure Checker

A self-hosted tool that scans a machine **you own** for risky open ports and tells you what's exposed, why it matters, and how to fix it.

## Use responsibly
Only scan systems you own or have **written permission** to test. Port-scanning machines you don't control is illegal in most places. By default this tool scans your own machine (`127.0.0.1`).

## Usage
```bash
python exposure_checker.py                 # scan your own machine
python exposure_checker.py 192.168.1.50    # scan a host on your own LAN
python exposure_checker.py --timeout 0.5   # faster scan, shorter per-port wait
```

## What it checks (Phase 1)
- ~28 commonly-risky ports: databases (MySQL, Postgres, MongoDB, Redis, Elasticsearch), remote access (SSH, RDP, VNC, Telnet), admin/dev panels, the Docker API, and legacy Windows services.
- Maps every open port to a severity, a plain-English reason, and a remediation tip, ordered worst-first.

## Roadmap
- **Phase 2:** Docker image CVE scan (Trivy), TLS certificate expiry, default-credential probes, SSH config audit.
- **Phase 3:** HTML report + a localhost-only web dashboard.

## Security notes (by design)
- **Pure Python standard library** - no third-party dependencies (no dependency-vuln surface) and **no shell calls** (no command-injection surface).
- **Validates the target** before connecting; defaults to your own machine.
- **No stored secrets**; scan results are git-ignored because they reveal your weak spots.
- **Localhost-first**: any future web UI will bind to `127.0.0.1` only.
