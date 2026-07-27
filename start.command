#!/bin/bash
# Double-click this file in Finder to start SSO Watcher.
# It will (1) set up the venv on first run, (2) kill any old instance
# still holding port 8765, then (3) start the sniffer.
# When done, press Ctrl-C in this Terminal window.

cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  echo "First-time setup — creating virtualenv and installing dependencies..."
  python3 -m venv .venv || {
    echo "!! Failed to create virtualenv. Do you have python3 installed?"
    read -p "Press Enter to close..."; exit 1;
  }
  .venv/bin/pip install -q -r requirements.txt || {
    echo "!! Failed to install dependencies."
    read -p "Press Enter to close..."; exit 1;
  }
fi

# Kill any leftover instance holding the port.
lsof -ti :8765 2>/dev/null | xargs kill -9 2>/dev/null

cat <<'BANNER'

===============================================
  SSO Watcher
  The dashboard will open in your browser once
  the server is up.
  Click  ▶ Start capture  to begin sniffing.
  Click  ■ Stop capture   to pause.
  Press  Ctrl-C  in this window to shut down.
===============================================

BANNER

sudo .venv/bin/python3 sso_watcher.py
