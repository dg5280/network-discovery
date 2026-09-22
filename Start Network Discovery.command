#!/bin/bash
# Double-click in Finder to start the dashboard. Close this window to stop it.
cd "$(dirname "$0")"
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is needed. macOS will offer to install it (Command Line Tools) — accept, then run this again."
  xcode-select --install 2>/dev/null
  read -n 1 -s -r -p "Press any key to close…"
  exit 1
fi
PY=python3
# Private environment inside this folder for the SSH library (nothing is installed system-wide).
if [ ! -x .venv/bin/python ]; then
  echo "First run: setting up a private Python environment for SSH support (one time, ~30 s)…"
  python3 -m venv .venv || echo "Couldn't create the private environment; SSH connect will be unavailable."
fi
if [ -x .venv/bin/python ]; then
  if ! .venv/bin/python -c "import paramiko" 2>/dev/null; then
    .venv/bin/python -m pip install --disable-pip-version-check -q -r requirements.txt \
      || echo "Couldn't install paramiko (offline?). Everything else works; SSH connect will be unavailable."
  fi
  PY=.venv/bin/python
fi
exec "$PY" -m netdisco "$@"
