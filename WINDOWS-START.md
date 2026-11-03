# Running WatchTower on this Windows PC

Installation completed in the existing Ubuntu-24.04 WSL2 distribution.
Python 3.12, PostgreSQL 16, the platform/API/worker packages, and Subfinder
are installed. Docker Desktop is not required for this installation.

Double-click **Start-WatchTower.cmd** to open the guided terminal menu.
The `local` project and owner account are already created. Choose **1 — Start
scan**, paste a domain or website link, confirm your target permissions, and
start. Saved domains and new targets are available in this same flow. Scans
open a separate Windows terminal, leaving Home available; results are saved
for later browsing.

Double-click **Start-Dashboard.cmd** to start the web server and open
http://localhost:8080. Keep its terminal window open while using the dashboard.
The browser opens after the server is ready.
Double-click **Copy-Dashboard-Token.cmd** to copy the private login token for
the currently selected terminal project,
then paste it into the dashboard's sign-in field. Ctrl+C stops the web server.

The start files start PostgreSQL automatically. Nothing scans until you
publish scope. Shipped detection rules remain pending maintainer approval;
the installation does not approve them. Notifications need your own optional
destination credentials.

## Runtime and data

The runtime is a separate Linux checkout of this repository at:

`/home/omid/.local/share/watchtower/app`

Its Python environment is `.venv`, configuration is `.env`, and evidence is
under `data/` relative to that directory. The token is stored privately at
`/home/omid/.config/watchtower/token`. PostgreSQL stores data in
`/var/lib/postgresql/16/main`; the application uses a restricted
`watchtower_local` role and database. Preserve these when backing up.

Code edits to the Windows checkout do not automatically update the Linux
runtime. Run code changes in the Linux checkout or intentionally update it
before reinstalling packages and applying any new migrations.

To run CLI commands from PowerShell:

```powershell
wsl -d Ubuntu-24.04 -- bash /home/omid/.local/share/watchtower/start.sh status
wsl -d Ubuntu-24.04 -- bash /home/omid/.local/share/watchtower/start.sh findings
```

The setup and token-copy helper scripts for this machine are included under
`files/windows/`. Generated runtime files, credentials, and backups remain ignored.
