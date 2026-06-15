"""Scoring, HTML report rendering, diff, and PDF export."""

import argparse
import datetime
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import time

from ._core import (
    _OS, _ps, _ps_quote, _shell_quote, _truncate,
    RISKY_PORTS, SPECIAL, SEVERITY_ORDER,
    _SCORE_WEIGHTS,
    _DEFAULT_BASELINE, _SMTP_CONFIG_PATH, _SCHEDULE_FILE,
    _Reporter, _NO_WINDOW,
)

# ── Diff ──────────────────────────────────────────────────────────────────────

def _save_baseline(path, data):
    """Persist report data as the baseline. Creates parent directories as needed."""
    parent = os.path.dirname(path)
    if parent:
        try:
            os.makedirs(parent, exist_ok=True)
        except OSError as e:
            return str(e)
    try:
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        return None
    except OSError as e:
        return str(e)


def _load_report(path):
    """Load and validate a saved JSON report. Returns (data, error_or_None)."""
    try:
        with open(path) as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return None, f"file not found: {path}"
    except json.JSONDecodeError as e:
        return None, f"invalid JSON in {path}: {e}"
    except OSError as e:
        return None, f"could not read {path}: {e}"
    if "checks" not in data or "timestamp" not in data:
        return None, f"{path} does not look like an exposure-checker report (missing 'checks' or 'timestamp')"
    return data, None


def diff_reports(before, after):
    """Compare two report dicts.  Returns:
        new      – (check, label, severity) found in after but not before
        resolved – (check, label, severity) found in before but not after
        changed  – (check, label, before_sev, after_sev) where severity shifted
    Findings are keyed by (check_name, label); duplicate keys keep the last entry.
    """
    def _index(data):
        idx = {}
        for check in data.get("checks", []):
            name = check.get("check", "")
            for f in check.get("findings", []):
                idx[(name, f.get("label", ""))] = f.get("severity", "UNKNOWN")
        return idx

    b, a = _index(before), _index(after)
    b_keys, a_keys = set(b), set(a)

    new      = sorted((k[0], k[1], a[k]) for k in a_keys - b_keys)
    resolved = sorted((k[0], k[1], b[k]) for k in b_keys - a_keys)
    changed  = sorted(
        (k[0], k[1], b[k], a[k])
        for k in b_keys & a_keys
        if b[k] != a[k]
    )
    return {"new": new, "resolved": resolved, "changed": changed}


def _print_diff(before_path, after_path, before_data, after_data, diff):
    b_ts = before_data.get("timestamp", "unknown")
    a_ts = after_data.get("timestamp", "unknown")

    print("=" * 66)
    print("  EXPOSURE CHECKER — DIFF")
    print(f"  Before : {b_ts}  ({before_path})")
    print(f"  After  : {a_ts}  ({after_path})")
    print("=" * 66)

    new, resolved, changed = diff["new"], diff["resolved"], diff["changed"]

    if not new and not resolved and not changed:
        print("\n[+] No changes between the two reports.\n")
        return

    if new:
        print(f"\nNEW ({len(new)}) ── findings that appeared:\n")
        for check, label, sev in sorted(new, key=lambda f: SEVERITY_ORDER.get(f[2], 9)):
            print(f"  [{sev}] {check} / {label}")

    if resolved:
        print(f"\nRESOLVED ({len(resolved)}) ── findings that disappeared:\n")
        for check, label, sev in sorted(resolved, key=lambda f: SEVERITY_ORDER.get(f[2], 9)):
            print(f"  [{sev}] {check} / {label}")

    if changed:
        print(f"\nCHANGED ({len(changed)}) ── severity shifted:\n")
        for check, label, b_sev, a_sev in sorted(
            changed, key=lambda f: SEVERITY_ORDER.get(f[3], 9)
        ):
            print(f"  [{b_sev} → {a_sev}] {check} / {label}")

    parts = []
    if new:      parts.append(f"{len(new)} new")
    if resolved: parts.append(f"{len(resolved)} resolved")
    if changed:  parts.append(f"{len(changed)} changed")
    print()
    print("-" * 66)
    print(f"  {' | '.join(parts)}")
    print("-" * 66)


def _diff_main(argv):
    parser = argparse.ArgumentParser(
        prog="exposure-checker diff",
        description="Compare two saved --output reports and show what changed.",
    )
    parser.add_argument("before", help="Baseline report (JSON file saved with --output).")
    parser.add_argument("after",  help="Current report (JSON file saved with --output).")
    parser.add_argument("--json", action="store_true",
                        help="Emit the diff as JSON.")
    parser.add_argument("--fail-on", metavar="SEVERITY",
                        choices=["critical", "high", "medium", "review", "info"],
                        type=str.lower,
                        help="Exit 1 if any NEW finding is at or above SEVERITY.")
    args = parser.parse_args(argv)

    before_data, err = _load_report(args.before)
    if err:
        sys.exit(f"[!] {err}")
    after_data, err = _load_report(args.after)
    if err:
        sys.exit(f"[!] {err}")

    diff = diff_reports(before_data, after_data)

    if args.json:
        print(json.dumps({
            "before":   {"file": args.before, "timestamp": before_data.get("timestamp")},
            "after":    {"file": args.after,  "timestamp": after_data.get("timestamp")},
            "new":      [{"check": c, "label": l, "severity": s} for c, l, s in diff["new"]],
            "resolved": [{"check": c, "label": l, "severity": s} for c, l, s in diff["resolved"]],
            "changed":  [{"check": c, "label": l, "before": b, "after": a}
                         for c, l, b, a in diff["changed"]],
        }, indent=2))
    else:
        _print_diff(args.before, args.after, before_data, after_data, diff)

    if args.fail_on:
        threshold = SEVERITY_ORDER.get(args.fail_on.upper(), 9)
        triggered = [(c, l, s) for c, l, s in diff["new"]
                     if SEVERITY_ORDER.get(s, 9) <= threshold]
        if triggered:
            if not args.json:
                print(
                    f"\n[!] --fail-on {args.fail_on}: "
                    f"{len(triggered)} new finding(s) at or above "
                    f"{args.fail_on.upper()}."
                )
            sys.exit(1)


# ── Risk score ────────────────────────────────────────────────────────────────

_SCORE_WEIGHTS = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 3, "REVIEW": 1, "INFO": 0}


def _compute_score(report_data):
    """Return (score 0–100, grade A–F). Each finding deducts weighted points."""
    deductions = 0
    for check in report_data.get("checks", []):
        for f in check.get("findings", []):
            deductions += _SCORE_WEIGHTS.get(f.get("severity", ""), 0)
    score = max(0, 100 - deductions)
    if score >= 90:   grade = "A"
    elif score >= 75: grade = "B"
    elif score >= 50: grade = "C"
    elif score >= 25: grade = "D"
    else:             grade = "F"
    return score, grade


# ── HTML report ────────────────────────────────────────────────────────────────

def _html_esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _render_html(report_data):
    """Return a self-contained HTML string for the given report."""
    score, grade = _compute_score(report_data)
    ts = report_data.get("timestamp", "")
    try:
        import datetime as _dt
        dt = _dt.datetime.fromisoformat(ts)
        ts_human = dt.strftime("%d %b %Y  %H:%M UTC")
    except Exception:
        ts_human = ts

    target = report_data.get("target", "localhost")

    # flatten findings
    all_findings = []
    for chk in report_data.get("checks", []):
        for f in chk.get("findings", []):
            all_findings.append({**f, "_check": chk.get("check", "")})

    counts = {}
    for f in all_findings:
        s = f.get("severity", "INFO")
        counts[s] = counts.get(s, 0) + 1

    # grade colour
    _gc = {"A": "#22a85c", "B": "#5ab033", "C": "#e69500", "D": "#d45400", "F": "#b22222"}
    grade_color = _gc.get(grade, "#888")

    # severity count pills
    pill_order = [("CRITICAL", "#b22222"), ("HIGH", "#c96a00"),
                  ("MEDIUM", "#c9a800"), ("REVIEW", "#777")]
    pills_html = ""
    for sev, bg in pill_order:
        n = counts.get(sev, 0)
        if n:
            pills_html += (
                f'<div style="text-align:center">'
                f'<div style="font-size:30px;font-weight:800;color:{bg}">{n}</div>'
                f'<div style="font-size:10px;font-weight:700;letter-spacing:1px;color:#888">{sev}</div>'
                f'</div>'
            )

    # ok checks (no findings, no error)
    ok_checks = [c["check"] for c in report_data.get("checks", [])
                 if not c.get("findings") and not c.get("error")]
    ok_html = ""
    if ok_checks:
        tags = "".join(
            f'<span style="background:#e8f5e9;color:#2e7d32;padding:3px 10px;'
            f'border-radius:3px;font-size:12px;font-weight:500;margin:3px 3px 0 0;'
            f'display:inline-block">{_html_esc(c)}</span>'
            for c in ok_checks
        )
        ok_html = (
            f'<div style="margin-top:28px">'
            f'<div style="font-size:11px;font-weight:700;letter-spacing:1.5px;'
            f'text-transform:uppercase;color:#888;margin-bottom:10px;padding-bottom:6px;'
            f'border-bottom:1px solid #e0e0e0">Passed checks</div>'
            f'{tags}</div>'
        )

    # findings cards grouped and sorted by severity
    sorted_findings = sorted(
        all_findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 9)
    )
    _badge_style = {
        "CRITICAL": "background:#b22222;color:#fff",
        "HIGH":     "background:#c96a00;color:#fff",
        "MEDIUM":   "background:#c9a800;color:#000",
        "REVIEW":   "background:#777;color:#fff",
        "INFO":     "background:#aaa;color:#000",
    }
    findings_html = ""
    for f in sorted_findings:
        sev = f.get("severity", "INFO")
        bs = _badge_style.get(sev, "background:#ccc;color:#000")
        fix_cmds = f.get("fix_cmds", [])
        cmds_html = ""
        if fix_cmds:
            cmds_html = '<div style="margin-top:8px">' + "".join(
                f'<code style="display:block;background:#1e1e1e;color:#9cdcfe;'
                f'padding:6px 10px;border-radius:3px;font-family:monospace;'
                f'font-size:12px;margin-top:4px">{_html_esc(c)}</code>'
                for c in fix_cmds
            ) + "</div>"
        findings_html += f"""
<details style="background:#fff;border:1px solid #e8e8e8;border-radius:4px;
                margin-bottom:6px;overflow:hidden">
  <summary style="display:flex;align-items:center;gap:10px;padding:11px 14px;
                  cursor:pointer;list-style:none">
    <span style="{bs};padding:2px 8px;border-radius:3px;font-size:11px;
                 font-weight:700;letter-spacing:0.5px;white-space:nowrap">{sev}</span>
    <span style="font-size:11px;color:#999;white-space:nowrap">{_html_esc(f.get('_check',''))}</span>
    <span style="font-weight:500;flex:1">{_html_esc(f.get('label',''))}</span>
  </summary>
  <div style="padding:2px 14px 12px;border-top:1px solid #f0f0f0">
    <p style="margin:8px 0 0;font-size:13px;color:#555">
      <strong>Why:</strong> {_html_esc(f.get('why',''))}
    </p>
    <p style="margin:6px 0 0;font-size:13px;color:#555">
      <strong>Fix:</strong> {_html_esc(f.get('fix',''))}
    </p>
    {cmds_html}
  </div>
</details>"""

    findings_section = (
        f'<div style="margin-bottom:28px">'
        f'<div style="font-size:11px;font-weight:700;letter-spacing:1.5px;'
        f'text-transform:uppercase;color:#888;margin-bottom:12px;padding-bottom:6px;'
        f'border-bottom:1px solid #e0e0e0">'
        f'Findings &mdash; {len(all_findings)} total</div>'
        f'{findings_html or "<p style=\'color:#22a85c;font-weight:600\'>No findings. Clean scan.</p>"}'
        f'</div>'
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Report — {_html_esc(target)}</title>
<style>
*,*::before,*::after{{box-sizing:border-box}}
body{{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
     font-size:14px;line-height:1.5;background:#f4f5f7;color:#1a1a1a}}
details summary::-webkit-details-marker{{display:none}}
details summary:hover{{background:#fafafa}}
@media print{{
  body{{background:#fff}}
  details{{open:true}}
  details:not([open]){{display:block}}
  details:not([open]) .finding-body{{display:block}}
}}
</style>
</head>
<body>
<div style="background:#111;color:#fff;padding:18px 40px;
            display:flex;justify-content:space-between;align-items:center">
  <div style="font-size:17px;letter-spacing:2px;font-weight:700">EXPOSURE CHECKER</div>
  <div style="text-align:right;font-size:12px;color:#888;line-height:1.9">
    Security Audit Report<br>
    Target: {_html_esc(target)}<br>
    {_html_esc(ts_human)}
  </div>
</div>

<div style="background:#fff;border-bottom:2px solid #e8e8e8;padding:22px 40px;
            display:flex;align-items:center;gap:32px">
  <div style="font-size:80px;font-weight:900;line-height:1;color:{grade_color}">{grade}</div>
  <div>
    <div style="font-size:32px;font-weight:700">{score}<span style="font-size:16px;
         color:#888;font-weight:400">/100</span></div>
    <div style="font-size:12px;color:#888;margin-top:2px">Risk Score</div>
  </div>
  <div style="display:flex;gap:24px;margin-left:auto">
    {pills_html}
  </div>
</div>

<div style="max-width:900px;margin:0 auto;padding:28px 20px">
  {findings_section}
  {ok_html}
  <div style="text-align:center;padding:20px 0 8px;font-size:11px;color:#bbb;
              border-top:1px solid #e8e8e8;margin-top:20px">
    Generated by Exposure Checker &mdash; self-hosted &mdash;
    your data never leaves this machine
  </div>
</div>
</body>
</html>"""


# ── Scan history ──────────────────────────────────────────────────────────────

_EC_DATA_DIR  = os.path.expanduser("~/.local/share/exposure-checker")
_HISTORY_DIR  = os.path.join(_EC_DATA_DIR, "history")
_ACCEPTED_FILE = os.path.join(_EC_DATA_DIR, "accepted_risks.json")


def generate_pdf_report(report_data: dict, path: str) -> str:
    """Generate a professional PDF report. Returns error string or empty string."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable,
        )
        from reportlab.lib.enums import TA_CENTER
    except ImportError:
        return "reportlab not installed — run: pip install reportlab"

    score, grade = _compute_score(report_data)
    ts  = report_data.get("timestamp", "")
    try:
        dt      = datetime.datetime.fromisoformat(ts)
        ts_human = dt.strftime("%d %b %Y  %H:%M UTC")
    except Exception:
        ts_human = ts

    grade_hex = {
        "A": "#34c96a", "B": "#00b4d8", "C": "#e8c13a",
        "D": "#f5922e", "F": "#f25757",
    }.get(grade, "#6b7786")

    sev_hex = {
        "CRITICAL": "#f25757", "HIGH": "#f5922e",
        "MEDIUM": "#e8c13a",   "REVIEW": "#6b7786", "INFO": "#888888",
    }

    doc  = SimpleDocTemplate(path, pagesize=A4, topMargin=2*cm,
                              bottomMargin=2*cm, leftMargin=2.5*cm,
                              rightMargin=2.5*cm)
    story = []

    hdr_style = ParagraphStyle("hdr", fontSize=22, fontName="Helvetica-Bold",
                                 spaceAfter=4, alignment=TA_CENTER)
    sub_style = ParagraphStyle("sub", fontSize=10, fontName="Helvetica",
                                 textColor=colors.HexColor("#555555"),
                                 spaceAfter=4, alignment=TA_CENTER)
    grade_style = ParagraphStyle("grade", fontSize=48, fontName="Helvetica-Bold",
                                  textColor=colors.HexColor(grade_hex),
                                  spaceAfter=2, alignment=TA_CENTER)
    score_style = ParagraphStyle("score", fontSize=14, fontName="Helvetica",
                                  textColor=colors.HexColor("#333333"),
                                  spaceAfter=2, alignment=TA_CENTER)
    sec_style   = ParagraphStyle("sec", fontSize=13, fontName="Helvetica-Bold",
                                  textColor=colors.HexColor("#111111"),
                                  spaceBefore=14, spaceAfter=6)
    body_style  = ParagraphStyle("body", fontSize=9, fontName="Helvetica",
                                  leading=13, textColor=colors.HexColor("#222222"),
                                  spaceAfter=3)
    muted_style = ParagraphStyle("muted", fontSize=8, fontName="Helvetica",
                                  textColor=colors.HexColor("#666666"),
                                  leading=12, spaceAfter=6)

    story.append(Spacer(1, 0.8*cm))
    story.append(Paragraph("Exposure Checker", hdr_style))
    story.append(Paragraph("Security Scan Report — Gull", sub_style))
    story.append(Paragraph(ts_human, sub_style))
    story.append(Spacer(1, 0.6*cm))
    story.append(HRFlowable(width="100%", thickness=1,
                              color=colors.HexColor("#dddddd")))
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph(grade, grade_style))
    story.append(Paragraph(f"Score: {score} / 100", score_style))
    story.append(Spacer(1, 0.6*cm))
    story.append(HRFlowable(width="100%", thickness=1,
                              color=colors.HexColor("#dddddd")))

    # Collect all findings sorted by severity
    all_findings = []
    for chk in report_data.get("checks", []):
        for f in chk.get("findings", []):
            all_findings.append((chk.get("check", ""), f))

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "REVIEW": 3, "INFO": 4}
    all_findings.sort(key=lambda x: sev_order.get(x[1].get("severity", ""), 5))

    if not all_findings:
        story.append(Spacer(1, 0.5*cm))
        story.append(Paragraph("No findings — system is clean.", body_style))
    else:
        story.append(Paragraph("Findings", sec_style))
        cur_sev = None
        for chk_name, f in all_findings:
            sev = f.get("severity", "INFO")
            if sev != cur_sev:
                cur_sev = sev
                story.append(Spacer(1, 0.3*cm))
                col = colors.HexColor(sev_hex.get(sev, "#888888"))
                tbl = Table([[Paragraph(sev, ParagraphStyle(
                    "sh", fontSize=8, fontName="Helvetica-Bold",
                    textColor=colors.white))]],
                    colWidths=[2*cm])
                tbl.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), col),
                    ("TOPPADDING",    (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                ]))
                story.append(tbl)

            label = f.get("label", "")
            why   = f.get("why", "")
            fix   = f.get("fix", "")

            row_data = [[
                Paragraph(f"<b>{_html_esc(label)}</b>", body_style),
                Paragraph(_html_esc(chk_name), muted_style),
            ]]
            row_tbl = Table(row_data, colWidths=[10*cm, 5*cm])
            row_tbl.setStyle(TableStyle([
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ("LEFTPADDING",   (0, 0), (0, -1), 10),
                ("LINEBELOW",     (0, 0), (-1, 0),
                 0.3, colors.HexColor("#eeeeee")),
            ]))
            story.append(row_tbl)
            if why:
                story.append(Paragraph(_html_esc(why), muted_style))
            if fix:
                story.append(Paragraph(
                    f"<font color='#00b4d8'>Fix: {_html_esc(fix)}</font>",
                    muted_style))

    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width="100%", thickness=0.5,
                              color=colors.HexColor("#dddddd")))
    story.append(Paragraph("Generated by Exposure Checker (self-hosted) — Gull",
                            muted_style))

    try:
        doc.build(story)
        return ""
    except Exception as exc:
        return str(exc)


# ── Snapshots ────────────────────────────────────────────────────────────────

_SNAPSHOT_DIR = os.path.expanduser("~/.local/share/exposure-checker/snapshots")
_SNAPSHOT_CAPTURED_FILES = [
    "/etc/ssh/sshd_config",
    "/etc/ld.so.preload",
]


