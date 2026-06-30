"""Pre-fix snapshot tracking — pure, no Tkinter.

Extracted verbatim from ``gui/app.py`` so the Tkinter UI and the webview bridge
share one implementation of the snapshot/revert gate. This logic is security-
critical: ``before_fix`` decides when a fix may proceed and what can later be
reverted (it aborts on an unreadable Linux/macOS config to protect the user's
files, while letting untrackable Windows registry/service fixes through). Keeping
it single-sourced means the two front-ends can never drift on that decision.
"""

import platform

import exposure_checker as ec

_OS = platform.system()  # "Linux" | "Darwin" | "Windows"


class _SessionTracker:
    """Captures pre-fix snapshots so everything applied this session can be reverted.

    On first successful before_fix() call the snapshot is also written to
    ~/.local/share/gullwing/sessions/<ts>/ so that an incomplete session
    (app killed mid-fix) is detectable on next launch.  mark_complete() is
    called when the user finishes a revert, adding a 'completed' sentinel.
    """

    def __init__(self):
        self._snaps:      list = []   # [(label, snap_dict)]
        self._session_ts: str  = ""   # set on first successful before_fix

    def before_fix(self, label: str) -> bool:
        """Capture pre-fix state. Returns True on success, False if snapshot failed.
        The caller MUST abort the fix if this returns False."""
        try:
            snap = ec.take_snapshot(label=f"before: {label}")
        except Exception:
            return False
        files      = snap.get("files", {})
        captured   = any(v is not None for v in files.values())
        has_net    = bool(snap.get("ufw_status") or snap.get("ufw_rules"))
        has_sysctl = any(v is not None for v in snap.get("sysctl_prev", {}).values())

        if captured or has_net or has_sysctl:
            # Real state captured — record it so the fix can be reverted.
            self._snaps.append((label, snap))
            # Persist to disk on the first snap in this session so an abrupt
            # kill leaves a recoverable manifest.
            if not self._session_ts:
                import datetime as _dt
                self._session_ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
            ec.write_session_manifest(self._session_ts, label, snap)
            return True

        # On Linux/macOS the captured files ARE what the fixes edit, so if they
        # exist on disk but came back as None (present but unreadable, e.g.
        # permission denied) a later revert would fail — abort to protect the
        # user's config. On Windows the captured hosts file is unrelated to the
        # registry/service fixes being applied, so an unreadable hosts file must
        # never block a fix.
        if _OS != "Windows" and any(v is None for v in files.values()):
            return False

        # Nothing on this system to snapshot (e.g. Windows fixes are registry/
        # service changes the snapshot system doesn't track). The fix isn't
        # revertable, but there's nothing to protect — let it proceed instead
        # of blocking the user outright.
        return True

    @property
    def has_changes(self):
        return bool(self._snaps)

    def earliest_snap(self):
        return self._snaps[0][1] if self._snaps else None

    def summary_lines(self):
        lines = []
        for label, snap in self._snaps:
            ts = snap.get("timestamp", "?")[:19].replace("T", " ")
            lines.append(f"[{ts}]  {label}")
        return lines

    def clear(self):
        """Clear in-memory state and mark the on-disk session as completed."""
        if self._session_ts:
            ec.mark_session_complete(self._session_ts)
            self._session_ts = ""
        self._snaps.clear()
