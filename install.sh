#!/usr/bin/env bash
# Install Exposure Checker into a local venv and link it into ~/.local/bin
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$REPO/.venv"

echo "Exposure Checker — installer"
echo ""

# Require Python 3.9+
if ! python3 -c "import sys; assert sys.version_info >= (3, 9)" 2>/dev/null; then
    echo "Error: Python 3.9 or newer is required."
    python3 --version 2>/dev/null || true
    exit 1
fi

echo "[1/3] Creating virtual environment..."
python3 -m venv "$VENV"

echo "[2/3] Installing dependencies..."
"$VENV/bin/pip" install --quiet -e "$REPO"

echo "[3/3] Linking to ~/.local/bin..."
mkdir -p "$HOME/.local/bin"
ln -sf "$VENV/bin/exposure-checker"    "$HOME/.local/bin/exposure-checker"
ln -sf "$VENV/bin/exposure-checker-ui" "$HOME/.local/bin/exposure-checker-ui"

# Warn if tkinter is missing (needed for the UI)
if ! "$VENV/bin/python" -c "import tkinter" 2>/dev/null; then
    echo ""
    echo "Note: tkinter not found — the desktop UI (exposure-checker-ui) won't work."
    echo "      On Debian/Ubuntu: sudo apt-get install python3-tk"
fi

# Warn if ~/.local/bin is not in PATH
case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *)
        echo ""
        echo "Note: ~/.local/bin is not in your PATH."
        echo "      Add this to your ~/.bashrc or ~/.zshrc:"
        echo '      export PATH="$HOME/.local/bin:$PATH"'
        ;;
esac

echo ""
echo "Done. Run:"
echo "  exposure-checker --full-audit"
echo "  exposure-checker-ui"
