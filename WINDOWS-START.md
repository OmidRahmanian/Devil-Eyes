# Running Devils Eyes on Windows

Devils Eyes runs inside Ubuntu on WSL2. You start it from Windows with the `.cmd` files in this folder. To install it, follow [Setup on Windows (WSL)](README.md#setup-on-windows-wsl) in the README.

## Everyday use

| File | What it does |
| --- | --- |
| `Start-Dashboard.cmd` | Starts PostgreSQL, the dashboard, the scan worker and the AI worker, then opens http://localhost:8080. **Keep its window open**, because scans and AI reviews run in it. Ctrl+C stops it. |
| `Start-WatchTower.cmd` | Opens the terminal menu (scans, progress, inventory, findings, continuous monitoring, AI review). |
| `Copy-Dashboard-Token.cmd` | Copies a sign-in token to the clipboard. You only need it to open the dashboard from another device; on this PC it opens without signing in. |

The `.cmd` files use the WSL distribution `Ubuntu-24.04`. For another distribution, run `setx DEVILS_EYES_DISTRO "<name from wsl -l -v>"` once and open a new window.

## Where things live (inside WSL)

| Path | Contents |
| --- | --- |
| `~/.local/share/watchtower/app` | The application, its `.venv` and its private `.env` |
| `~/.local/share/watchtower/start.sh` | The entry point the `.cmd` files call (a copy of `deploy/windows/start.sh`) |
| `~/.config/watchtower/` | Private tokens (mode 600) |
| PostgreSQL data directory | All projects, scans, findings and AI reviews |

Back these up together.

## Running CLI commands from PowerShell

```powershell
wsl -d Ubuntu-24.04 --cd ~ -- bash .local/share/watchtower/start.sh status
wsl -d Ubuntu-24.04 --cd ~ -- bash .local/share/watchtower/start.sh --help
```

Any `watchtower` command works after `start.sh`, for example `start.sh findings`.

## Updating

Close the dashboard and terminal windows, then run this inside Ubuntu:

```bash
cd ~/.local/share/watchtower/app
git pull
.venv/bin/python -m pip install -e '.[api,workers]' -r requirements.txt
set -a; . ./.env; set +a
.venv/bin/watchtower-db upgrade
cp deploy/windows/start.sh ~/.local/share/watchtower/start.sh
```

Then start the dashboard again and press **Ctrl+Shift+R** in the browser.
