# Post-Mortem — macOS & Windows builds "not working"

**Scope:** v1.0 hardening pass. Why the macOS `.dmg` and Windows `.exe` behaved
incorrectly (or didn't build at all), what the root causes were, and how each is
prevented going forward.

This is written blameless and mechanism-first: every entry names the *defect*,
the *mechanism* by which it produced the observed symptom, the *fix*, and the
*guardrail* that keeps it from regressing.

---

## TL;DR

The app was correct in spirit but wrong in a dozen platform-specific details.
None of the failures were in the security logic — they were all in the seams
between Python and the host OS (console handling, encoding, privilege prompts,
DPI, URI formats, the unified log, scheduling, and the freeze/unfreeze
boundary). The single highest-impact defect was a **frozen-app entry point that
ignored CLI arguments**, which silently broke scheduled scans. The most
*user-visible* defect on Windows was the **Defender false-positive storm** on
machines running Norton/Bitdefender.

A regression test now exists for every parser and heuristic changed here
(`tests/test_new_features.py`, 30 tests). Two of those tests caught real bugs
*during* this pass — see "What the tests caught," below.

---

## Severity 1 — Showstoppers

### S1.1 Frozen binary ignored CLI args → scheduled scans launched the GUI
- **Mechanism.** The PyInstaller bundle's entry point is `exposure_checker_ui.py`,
  whose `main()` unconditionally created a Tk window. The scheduler re-invokes
  the app as `exposure-checker headless --tabs …`. The frozen binary received
  those args, ignored them, and opened the GUI on a machine where nobody was
  watching — so the scheduled scan never ran and produced no notification.
- **Fix.** `main()` now inspects `sys.argv`; if the first token is a known
  subcommand (`headless`, `schedule`, `diff`, `remediate`) or a flag, it
  delegates to the scanner's CLI handler *before* touching Tk.
- **Guardrail.** Verified by actually building with PyInstaller and running
  `./dist/exposure-checker --version` and `… headless --tabs cleaner` headlessly.
  Both now work from the frozen binary.

### S1.2 Schedules baked the PyInstaller temp path into cron/launchd/Task Scheduler
- **Mechanism.** Schedule installers used `os.path.abspath(__file__)`. In a
  one-file PyInstaller build, `__file__` lives under the `_MEIPASS` temp dir that
  is **deleted when the app exits**. Every scheduled entry therefore pointed at a
  path that no longer existed minutes later.
- **Fix.** New `_self_invocation()` returns `[sys.executable]` when
  `sys.frozen` is set (re-launch the binary itself) and
  `[sys.executable, abspath(__file__)]` from source. All three installers
  (cron, launchd, Task Scheduler) now use it.
- **Guardrail.** `TestSelfInvocation` covers both the source and frozen branches.

### S1.3 Build spec
- **Status.** `exposure_checker.spec` is present and valid; a clean
  `pyinstaller exposure_checker.spec` produces a runnable binary (validated on
  Linux in this pass). The release workflow references it correctly.
- **Guardrail.** Keep the build job in CI as the canary — if the spec ever goes
  missing again the `Build & Release` job fails loudly on tag push.

---

## Severity 2 — Windows correctness

### S2.1 Defender false-positive storm (the big one)
- **Mechanism.** The malware check flagged a **CRITICAL "Defender disabled"** on
  every machine running a third-party AV — because Windows *intentionally*
  disables Defender when Norton/Bitdefender/etc. is active. It also reported
  `Get-MpThreatDetection` history (already-quarantined items) as **"Active
  threat."** Both fire on healthy machines, destroying trust in the product.
- **Fix.** New `_win_third_party_av()` reads `root/SecurityCenter2`'s
  `AntiVirusProduct`; if an enabled non-Defender AV is registered, Defender
  standing down is reported as *normal*, not critical. Active threats now come
  from `Get-MpThreat | Where IsActive`, excluding historical detections.
- **Guardrail.** `TestDefenderFalsePositives` (6 tests) covers: third-party AV
  suppresses CRITICAL; genuinely-no-AV is still CRITICAL; empty threat list
  produces no "active threat"; and the product-state enabled-bit decoding.

### S2.2 PowerShell console flash + UnicodeDecodeError
- **Mechanism.** Every `_ps()` call spawned a visible console window in the
  windowed app, and `text=True` decoding crashed on the OEM code page on
  non-English Windows.
- **Fix.** `_ps()` now passes `creationflags=CREATE_NO_WINDOW` and
  `errors="replace"`.

### S2.3 `winget upgrade --list` is an invalid flag
- **Mechanism.** Modern winget (≥1.4) rejects `--list`; the subprocess errored
  and the check silently reported "no upgrades" everywhere.
- **Fix.** Correct flags (`--include-unknown --accept-source-agreements
  --disable-interactivity`) plus a robust `_parse_winget_upgrade_count()` that
  prefers the "N upgrades available" line and falls back to counting table rows.
- **Guardrail.** `TestWingetParse` (4 tests).

### S2.4 Duplicate listeners, noisy SYSTEM tasks
- **Mechanism.** Dual-stack services bind both `0.0.0.0` and `::`, so every
  listener was reported twice. Built-in `\Microsoft\` tasks legitimately run as
  SYSTEM and buried real findings.
- **Fix.** Listeners deduped by `(port, pid)`; scheduled-task check excludes the
  `\Microsoft\` path.

### S2.5 Blurry UI on HiDPI; "Open Report" failed
- **Mechanism.** No DPI awareness → Windows bitmap-stretched the window (blurry).
  `webbrowser.open(f"file://{path}")` produced a malformed URI on Windows
  (drive letters, backslashes).
- **Fix.** `SetProcessDpiAwarenessContext` (with fallbacks) + Tk scaling synced
  to system DPI; report opened via `pathlib.Path(...).resolve().as_uri()`.

### S2.6 One UAC prompt per fix
- **Mechanism.** Each fix command spawned its own elevated process → a UAC
  consent dialog *per fix*.
- **Fix.** All fix commands run inside one elevated, marker-tagged PowerShell
  script; output captured via a redirect file (since `-Verb RunAs` can't pipe
  stdout back). One prompt for the whole batch.

---

## Severity 2 — macOS correctness

### S2.7 Cleaner tab did nothing
- **Mechanism.** The macOS path fell through to the Linux apt/dpkg/journalctl
  branch, which finds nothing on a Mac.
- **Fix.** Full macOS cleaner: user caches, Trash, logs, Xcode DerivedData, iOS
  backups, `brew cleanup` estimate, stale temp files — plus the shared
  browser/dev-cache scanner.

### S2.8 Antivirus scanned the wrong filesystem
- **Mechanism.** The AV check scanned Linux paths (`/home`, `/dev/shm`) that
  don't exist on macOS, and detected only ELF binaries — never Mach-O.
- **Fix.** macOS AV path scans `/Users`, `/private/tmp`, `/Users/Shared`; adds
  Mach-O magic detection (32/64-bit, both endiannesses, universal), launchd-plist
  persistence scanning, a Gatekeeper-disabled check, and XProtect freshness.
- **Guardrail.** `TestMachODetection`, `TestMacPersistence` (Gatekeeper +
  launchd persistence), `TestMacFirewall`.

### S2.9 Firewall reported "no firewall" for normal users
- **Mechanism.** `pfctl` requires root and silently fails otherwise, producing a
  false "no active firewall."
- **Fix.** Read `com.apple.alf globalstate` first (works without root); only
  trust a *positive* pfctl result.

### S2.10 Unified-log query timed out; trackpad scroll dead
- **Mechanism.** `log show --last 24h` routinely exceeds 30 s → surfaced as a
  scan error. And `int(delta/60)` truncates macOS's small scroll deltas to 0, so
  the findings pane couldn't be scrolled.
- **Fix.** 6 h window with a 60 s budget and graceful skip; per-platform scroll
  handling (`-int(delta)` on macOS, `/120` on Windows, button-4/5 on X11).

### S2.11 One admin password prompt per fix
- **Fix.** Same pattern as Windows — all commands in one `do shell script …
  with administrator privileges` behind a single prompt.

---

## What the tests caught (this pass, not in production)

Writing the regression tests *before* declaring victory paid off immediately:

1. **`json.loads("null")` → `None`** crashed `_win_third_party_av()` whenever
   `SecurityCenter2` returned no products. Caught by
   `test_no_av_at_all_is_critical`.
2. **"Bitdefender" contains "defender."** The first cut of the false-positive fix
   excluded any product whose name contained the substring `defender`, which
   silently excludes *Bitdefender itself* — meaning Bitdefender users would still
   get the false CRITICAL. Caught by `test_third_party_av_enabled_bit`. The fix
   now matches `windows defender` / `microsoft defender` specifically.

Both are exactly the class of bug that ships when you reason about Windows AV
from memory instead of testing the decoding.

---

## Themes & prevention

- **The freeze boundary is a different runtime.** `__file__`, the working dir,
  bundled data, and the entry point all behave differently once frozen. Anything
  that re-invokes the app, or reads a path relative to itself, must be tested
  against the *built binary*, not the source. CI's build job is the guardrail.
- **The OS is non-English, non-root, and high-DPI by default.** Encoding,
  privilege, and scaling assumptions that hold on the developer's machine are the
  first things to break in the field. Each now has an explicit fix.
- **Security tools must not cry wolf.** A false CRITICAL is worse than a missed
  INFO, because it trains the user to ignore the product. The Defender and
  firewall false positives were the most damaging defects even though they were
  trivial to fix.
- **Honest architecture.** This is an *orchestrator*: it drives the OS-native
  engines (Defender / XProtect / ClamAV; Windows Firewall / pf / alf) with
  heuristics layered on top, 100% local, zero telemetry. A resident AV engine and
  packet-filtering firewall are deliberately *not* reimplemented in Python — that
  would be slower, weaker, and dishonest. The value is correct orchestration plus
  plain-language remediation.

---

## Verification performed

- `pytest`: 200 passed, 2 skipped (root-guarded permission tests).
- `pyinstaller exposure_checker.spec`: clean build; binary runs; `--version` and
  headless scans work from the frozen executable.
- UI smoke test under a virtual display: app constructs, a live Cleaner scan runs
  to an A/100 result, the Venice splash renders all frames without error.
