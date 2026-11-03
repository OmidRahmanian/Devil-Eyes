#!/usr/bin/env bash
set -euo pipefail
cd /home/omid/.local/share/watchtower/app
export PATH="$PWD/.venv/bin:$PATH"
set -a
source .env
set +a
case "${1:-menu}" in
  menu) exec python launcher.py --platform ;;
  dashboard) exec python terminal_ui.py --dashboard --open-browser ;;
  status) exec watchtower status ;;
  migrate) exec watchtower-db upgrade ;;
  bootstrap)
    if [ ! -s /home/omid/.config/watchtower/token ]; then
      watchtower bootstrap local --name "Local WatchTower" --owner "Omid" --save-token /home/omid/.config/watchtower/token
    fi
    ;;
  *) exec watchtower "$@" ;;
esac
