# Getting Started with Gullwing

A two-minute orientation for your first run. Gullwing is fully local — nothing
leaves your machine, no account, no telemetry.

---

## 1. Launch it

| Platform | First run |
|---|---|
| **Windows** | `powershell -ExecutionPolicy Bypass -File scripts\install.ps1`, then launch **Gullwing** from the Start menu (or run `gullwing-ui`). |
| **macOS** | `bash scripts/install.sh`, then open **Gullwing** from Spotlight (or run `gullwing-ui`). |
| **Linux** | `sudo apt install python3-tk -y`, then `bash scripts/install.sh`, and search **Gullwing** in your launcher. |

Run without installing, from the repo root:

```bash
python -m exposure_checker.gui.app
```

On Windows and macOS the app asks for administrator/root access at launch, because
applying fixes (firewall, registry, services) needs it. On Linux it scans as a
normal user and only elevates per-fix via `pkexec`/`sudo` when required.

---

## 2. Scan

Pick a tab from the left nav rail (Security, Antivirus, Performance, Protection,
Cleaner, …) and press **Scan**. Each finding shows:

- a **severity** (Critical → Info),
- a plain-English explanation of *why* it matters, and
- a **Fix** button where a one-click fix exists.

**About your score:** only findings Gullwing can actually fix count against your
grade. Informational items and things that need a BIOS or hardware change (e.g.
"enable Secure Boot") are shown but never lower your score — so applying the
offered fixes is always enough to reach an A.

---

## 3. Fix — and what you're agreeing to

Clicking **Fix** does **not** run anything immediately. You first see the exact
shell / PowerShell / registry command(s) and confirm them. You can also use
**Copy Commands** to run them yourself in a terminal instead.

Before changing a config file, Gullwing snapshots it so the change can be undone.

---

## 4. Revert — what it does and doesn't cover

**Revert Session** rolls back the changes made in your current session.

- **Survives a restart?** Yes. Snapshots are written to disk, so if Gullwing is
  closed or crashes mid-fix, it offers to finish the rollback next time you open it.
- **Covers config fixes?** Yes — SSH config, firewall rules, sysctl, hosts.
- **Covers Cleaner deletions?** **No.** Deleting cached/temp files frees space but
  can't be undone; those findings are labelled **"Cannot be undone."**
- **Covers Windows registry/service tweaks?** **No.** On Windows the snapshot only
  captures the hosts/firewall state; registry and service changes aren't tracked.
  Use **System Restore** if you need a full Windows rollback.

In short: *most security and config changes revert in one click; file deletions
and some Windows changes cannot.*

---

## 5. Other things worth knowing

- **Accept Risk** dismisses a finding you've reviewed so it won't nag you next scan.
- **Snapshots tab** lets you save/restore a point-in-time config backup at any time.
- **Reports** can be exported as HTML or PDF; **Save Baseline** + **Diff vs File**
  let you track changes over time.
- **Where your data lives:** `%APPDATA%\gullwing` (Windows),
  `~/Library/Application Support/gullwing` (macOS), `~/.local/share/gullwing` (Linux).

That's it — scan, review, fix what you're comfortable with, and revert if you
change your mind.
