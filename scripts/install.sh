#!/usr/bin/env bash
# Install Gullwing — run this once, then double-click from your app launcher
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$REPO/.venv"
DESKTOP_DIR="$HOME/.local/share/applications"
DESKTOP_FILE="$DESKTOP_DIR/gullwing.desktop"

echo "Gullwing — installer"
echo ""

# ── Python check ──────────────────────────────────────────────────────────────
if ! python3 -c "import sys; assert sys.version_info >= (3, 9)" 2>/dev/null; then
    echo "Error: Python 3.9 or newer is required."
    python3 --version 2>/dev/null || true
    exit 1
fi

# ── tkinter check ─────────────────────────────────────────────────────────────
if ! python3 -c "import tkinter" 2>/dev/null; then
    echo "Error: tkinter not found. Install it first:"
    echo "  Ubuntu/Debian:  sudo apt install python3-tk"
    echo "  Fedora:         sudo dnf install python3-tkinter"
    echo "  Arch:           sudo pacman -S tk"
    exit 1
fi

echo "[1/4] Creating virtual environment..."
python3 -m venv "$VENV"

echo "[2/4] Installing dependencies..."
# Install with the pygame splash extra; fall back to the base install if the
# pygame wheel is unavailable for this platform/Python.
"$VENV/bin/pip" install --quiet -e "$REPO[splash]" \
    || "$VENV/bin/pip" install --quiet -e "$REPO"

echo "[3/4] Linking CLI to ~/.local/bin..."
mkdir -p "$HOME/.local/bin"
ln -sf "$VENV/bin/gullwing"    "$HOME/.local/bin/gullwing"
ln -sf "$VENV/bin/gullwing-ui" "$HOME/.local/bin/gullwing-ui"

echo "[4/4] Installing desktop launcher..."
mkdir -p "$DESKTOP_DIR"
cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Version=1.0.8
Name=Gullwing
Comment=Tune it. Lock it. Send it.
Exec=$HOME/.local/bin/gullwing-ui
Icon=utilities-system-monitor
Terminal=false
Type=Application
Categories=System;Security;Utility;
StartupNotify=true
EOF
chmod +x "$DESKTOP_FILE"
update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true

# ── PATH warning ──────────────────────────────────────────────────────────────
case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *)
        echo ""
        echo "Note: ~/.local/bin is not in your PATH."
        echo "      Add to your ~/.bashrc or ~/.zshrc:"
        echo '      export PATH="$HOME/.local/bin:$PATH"'
        ;;
esac

echo ""
echo "Done!"
echo "  • Search 'Gullwing' in your app launcher and double-click it"
echo "  • Or run from terminal: python3 \"$REPO/gullwing_ui.py\""
