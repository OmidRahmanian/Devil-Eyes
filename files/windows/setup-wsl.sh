#!/usr/bin/env bash
set -euo pipefail
umask 077
SOURCE="$(cd "$(dirname "$0")/../.." && pwd)"
APP=/home/omid/.local/share/watchtower/app
mkdir -p "$(dirname "$APP")"
if [ ! -e "$APP" ]; then
  git clone --no-hardlinks "$SOURCE" "$APP"
  git -C "$APP" remote set-url origin https://github.com/OmidRahmanian/Devil-Eyes.git
fi
cd "$APP"
if [ ! -x .venv/bin/python ]; then python3 -m venv .venv; fi
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[api,workers]' -r requirements.txt
.venv/bin/python "$SOURCE/files/windows/configure-wsl.py"
cp "$SOURCE/files/windows/start-wsl.sh" /home/omid/.local/share/watchtower/start.sh
cp "$SOURCE/files/windows/dashboard-token.py" /home/omid/.local/share/watchtower/dashboard-token.py
printf '\nWatchTower packages installed.\n'
