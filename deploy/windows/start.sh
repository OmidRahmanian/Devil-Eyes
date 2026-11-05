#!/usr/bin/env bash
# Entry point for the Windows start files (Start-WatchTower.cmd, Start-Dashboard.cmd).
# Copy it to ~/.local/share/watchtower/start.sh inside WSL; the app lives next to it in app/.
set -euo pipefail
cd "$HOME/.local/share/watchtower/app"
export PATH="$PWD/.venv/bin:$PATH"
set -a
source .env
set +a
case "${1:-menu}" in
  menu) exec python launcher.py --platform ;;
  dashboard) exec python terminal_ui.py --dashboard --open-browser ;;
  token) exec python deploy/windows/dashboard-token.py ;;
  status) exec watchtower status ;;
  migrate) exec watchtower-db upgrade ;;
  *) exec watchtower "$@" ;;
esac
