#!/bin/bash
# Launch Gullwing. Prefer the project venv (which has the optional pygame+numpy
# splash deps); fall back to system python3 if there's no venv.
cd "$(dirname "$0")/.."
if [ -x ".venv/bin/python" ]; then
    exec .venv/bin/python gullwing_ui.py "$@"
fi
exec python3 gullwing_ui.py "$@"
