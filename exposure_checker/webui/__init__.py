"""Gullwing HUD — webview front-end package.

A pywebview (Qt/WebEngine) shell that renders the HUD design as local HTML/CSS/JS
and exposes Gullwing's real scan/fix/revert/clean/benchmark/overclock logic to it
through :class:`exposure_checker.webui.bridge.Bridge`. No network, no telemetry —
the page is loaded from disk and locked down with a strict CSP.
"""
