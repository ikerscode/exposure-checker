# Gullwing — Product Roadmap & Design Vision

> Written as the founding engineer/designer's plan to take Gullwing from a great
> tool to *the* PC companion. Grounded in 2026 market research of CCleaner,
> Razer Cortex, Glary Utilities, Wise Care 365, Iolo System Mechanic and others.

---

## 1. Positioning — what we are

**Gullwing is the trustworthy, all-in-one, local-first PC companion.**

The market splits into three camps, and each has a fatal gap:

| Competitor type | Example | Their gap |
|---|---|---|
| Cleaners | CCleaner, Wise Care | Telemetry/trust scandals; cleaning only |
| Game boosters | Razer Cortex | Closed, gaming-only, account-gated |
| Utility suites | Glary, System Mechanic | Cluttered, Windows-only, upsell-heavy |

**Our wedge:** one app that does security + malware + performance + cleaning +
benchmark + overclock advisory, on Win/macOS/Linux, that **provably keeps
everything local and reversible.** The thing the others can't copy is the trust
posture — you can't leak what you never collect.

### One-line pitch
> *"The all-in-one tune-up your PC actually deserves — every fix local, every change reversible, nothing ever phones home."*

---

## 2. The three pillars (defend these in every decision)

1. **Trust.** Local-only, no telemetry, no account, transparent commands, full
   undo. This is the moat. Never add a feature that compromises it.
2. **Breadth with depth.** Six tools in one, each genuinely good — not a menu of
   shallow gimmicks.
3. **Craft.** It should feel like a premium product: the cinematic splash, the
   live hardware monitor, smooth animations, thoughtful copy.

---

## 3. Roadmap

### NOW (shipped in 1.0.8)
- ✅ Cinematic pygame+numpy splash (rippled water, bloom, god-rays, gulls).
- ✅ Time-budgeted, never-hanging AV/Cleaner scans.
- ✅ Opera-GX live overclock monitor; advisory diff-render (no flicker).
- ✅ Snapshot/Revert, Accept-Risk, Copy-Commands, disk-space pre-flight.

### NEXT (1.1 — highest ROI, low risk)
1. **One-click "Tune-Up" dashboard (home tab).** A single hero screen with an
   overall health score (0–100, A–F), the four sub-scores (Security /
   Performance / Cleanable / Protection), and one big **Optimize** button that
   runs all scans and offers a batched fix list. *This is the #1 thing every
   competitor leads with and we currently make the user hunt across tabs.*
2. **Scheduled auto-scan + tray notifications.** We already have the scheduler
   backend (`_schedule.py`); surface it in the UI: "Scan weekly, notify me only
   if something's CRITICAL." Marketable as "set and forget."
3. **Privacy cleaner module.** Clear browsing history/cookies/recent-docs and a
   **secure file shredder** (multi-pass overwrite). Research shows privacy +
   shredding is a top marketable feature and we have most of the plumbing.
4. **Before/After proof.** After a fix run, show "Freed 3.2 GB · Boot items 12→7
   · Score 64→88." Tangible results drive word-of-mouth and reviews.
5. **Profiles.** "Gaming", "Work", "Battery", "Quiet" one-click presets that
   apply a curated set of performance tweaks (and revert on profile switch).

### LATER (1.2+ — differentiation & delight)
6. **Live FPS/latency overlay hooks** (MangoHud/PresentMon integration) to rival
   Razer Cortex without freezing processes.
7. **Trend history & sparklines** for each score (we store history already) —
   "your security score over the last 30 days."
8. **Per-finding "Learn more" cards** — short, plain-English security/perf
   education. Turns the tool into a teacher; great for retention & shareability.
9. **Themeable UI** (Midnight / Aurora / Mono) and an accent-color picker.
10. **Portable + installed builds**, signed binaries (removes SmartScreen/
    Gatekeeper friction — a real adoption blocker for indie tools).
11. **Optional encrypted local report export** (PDF/HTML already exist) with a
    shareable "clean bill of health" certificate.

---

## 4. UX / UI design direction (per screen)

**Global**
- Adopt a persistent left **rail nav** (icons + labels) instead of top tabs —
  scales better to 6+ modules and reads as "premium app", not "utility".
- A persistent top **health header**: overall grade chip, last-scan time, and a
  single **Optimize** CTA. Consistent across all screens.
- Motion language: 150–200 ms ease-out for state changes, subtle accent glows
  (already used in the OC monitor) — never gratuitous.

**Home / Dashboard (new)**
- Hero radial gauge for overall score; four secondary gauges; a live "what we
  found" feed; one primary CTA. This is the screen in every marketing
  screenshot.

**Findings screens**
- Keep the severity-colored cards. Add: filter chips (All/Critical/Fixable),
  a sticky "Fix all (N)" bar, and inline expand for the exact command.

**Cleaner**
- Animated reclaimable-space bar that fills as the scan runs; per-category
  checkboxes with sizes; a satisfying "freed X" result animation.

**Benchmark & Overclock**
- Already strong (animated village + live monitor). Add a shareable result card
  (score + tier + key numbers) export as PNG.

**Splash**
- Done. Consider a 2-second "fast path" splash for repeat launches so power
  users aren't waiting on the full 7 s every time (preference toggle).

---

## 5. Trust & go-to-market

- **Lead with privacy** in every store listing/screenshot: "No account. No
  telemetry. No cloud. Open about every command it runs."
- **Reproducible, signed releases** + a published SHA list. Indie security tools
  live or die on this.
- **A 60-second demo GIF** of: splash → one-click Optimize → "Freed 3 GB, score
  64→88" → Revert. That loop is the entire sell.
- **Comparison table** on the landing page vs CCleaner/Razer: "all-local",
  "reversible", "cross-platform", "all-in-one" are our green checks.
- **Pricing (if ever):** core stays free & local (trust); a one-time "Pro"
  unlock for profiles, scheduling, and themes. Never subscriptions, never
  data — that would betray the pillar.

---

## 6. Explicitly out of scope (protect the brand)
- ❌ Any telemetry, "anonymous usage stats", or phone-home update checks.
- ❌ Bundled toolbars / PUPs / "driver updater" upsells (the genre's cancer).
- ❌ Auto-applying overclock voltages/frequencies (advisory only, forever).
- ❌ Cloud accounts or login walls.

---

*The north star: a tool so honest, capable, and beautiful that recommending it
feels like doing a friend a favor.*
