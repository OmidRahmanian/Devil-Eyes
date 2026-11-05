# Setup guideline for AI assistants

This file is for an AI coding assistant that a user has asked to install and start Devils Eyes (package name `watchtower`) for them. It is a **guideline, not a script**. Read it fully, follow the steps in order, verify each step before moving on, and keep the user informed.

The human-facing version of these steps is in [README.md](README.md). When the two differ, follow the README and tell the user about the difference.

## Ground rules

These are not optional. Devils Eyes is a security tool that sends real network requests, so the setup must not weaken its safeguards.

1. **Ask before anything that changes the system.** That covers `sudo`, installing packages, `wsl --install`, downloading binaries and creating database roles. Say what the command does and wait for a yes. Read-only checks (versions, `status`, `ls`) need no permission.
2. **Never add targets, publish scope or start scans yourself.** Scanning needs the user's own authorization for each domain, and the user must enter it and tick the confirmation themselves. Do not fill in the authorization or attestation for them, and do not suggest domains to test.
3. **Never approve detection rules.** The rules in `rules/` ship pending maintainer approval on purpose. Do not edit `rules/manifest.json` or pin hashes to "make the scan complete". A **partial** scan result is expected and correct.
4. **Never expose secrets.** Do not print, log, paste into chat or commit `.env`, database passwords, API tokens (`wt_...`), the files in `~/.config/watchtower/`, or webhook URLs. Generate passwords on the machine and write them straight into `.env` with mode 600. Check `git status` before any commit; `.env` must not appear in it.
5. **Do not weaken security settings to get past an error.** Specifically:
   - Never connect the app as a PostgreSQL superuser or a `BYPASSRLS` role.
   - Never set `scope.allow_private_networks`.
   - Never add `--allow-remote` or listen on `0.0.0.0` unless the user asks for access from other devices; it also needs TLS.
   - Never relax the dashboard's Content-Security-Policy.
   - Never disable the egress guard.

   If something only works with one of these changed, stop and explain the problem to the user instead.
6. **Use only local AI.** The AI review talks to a model on the user's machine (Ollama). Do not configure an online AI provider or a public endpoint. The app refuses one anyway.
7. **Don't delete data.** Projects are archived, never deleted. Do not drop the database, delete `data/` or remove the user's existing installation without an explicit request.
8. **Stop on unexpected output.** If a command fails in a way this guide does not cover, show the user the relevant error (with secrets removed) and propose a fix. Do not guess repeatedly.

## Step 0: find out where you are

Run read-only checks and tell the user what you found:

| Check | Command |
| --- | --- |
| Operating system | Windows: `ver` / `wsl -l -v`. Linux/macOS: `uname -a`, `cat /etc/os-release` |
| Python 3.11+ | `python3 --version` (inside WSL on Windows) |
| PostgreSQL | `psql --version`; on Linux/WSL, `service postgresql status` |
| Git | `git --version` |
| Existing install | `ls ~/.local/share/watchtower/app` (Windows/WSL layout) or a checkout the user points to |
| Port 8080 free | `curl -s http://127.0.0.1:8080/api/v1/health`; any answer means something already runs there |

If an installation already exists, **do not reinstall over it**. Ask whether to update it (Step 9) or leave it.

Then choose the path:

- **Windows:** everything runs inside WSL2 Ubuntu, in `~/.local/share/watchtower/app`. The `.cmd` files depend on that path.
- **Linux:** any checkout directory.
- **macOS:** any checkout directory, with PostgreSQL from Docker (`deploy/compose.yaml`) or Homebrew.

## Step 1: WSL (Windows only)

- If `wsl -l -v` lists no Ubuntu distribution, ask the user to run `wsl --install -d Ubuntu-24.04` in an **Administrator** PowerShell, then restart and create their Linux user. They have to do the user creation interactively.
- Note the distribution name. If it is not `Ubuntu-24.04`, the user must run `setx DEVILS_EYES_DISTRO "<name>"` so the `.cmd` files find it.
- From here on, run every command **inside** that distribution: `wsl -d <name> -- bash -lc '...'`, or ask the user to paste them into the Ubuntu terminal.

**Verify:** `wsl -d <name> -- uname -a` prints a Linux kernel.

## Step 2: system packages

With permission (this uses `sudo`):

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip postgresql unzip curl
sudo service postgresql start
```

`sudo` asks for the user's Linux password. Let the user type it; never ask them to tell it to you.

**Verify:** `python3 --version` shows 3.11 or newer, and `sudo -u postgres psql -Atc 'select version()'` prints a PostgreSQL version.

## Step 3: code and Python environment

```bash
mkdir -p ~/.local/share/watchtower
git clone https://github.com/OmidRahmanian/Devil-Eyes.git ~/.local/share/watchtower/app   # Windows/WSL layout
cd ~/.local/share/watchtower/app
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[api,workers]' -r requirements.txt
```

**Verify:** `.venv/bin/watchtower --help` and `.venv/bin/watchtower-db --help` both print usage.

## Step 4: database

Follow README step "Create the database" exactly. In summary:

- Create the role `watchtower` with `LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS` and a password from `secrets.token_hex(32)`, generated in the shell. Never invent or echo it.
- Create the database `watchtower` owned by that role, with the same `REVOKE`/`GRANT`/`ALTER SCHEMA` statements.
- Write `.env` with `umask 077`, containing only `WATCHTOWER__DATABASE__URL=...` and `WATCHTOWER_PROFILE=development`.
- Load `.env` and run `.venv/bin/watchtower-db upgrade`.

If the role or database already exists, **stop and ask**. It may belong to an earlier install whose password is in an existing `.env`.

**Verify:**
- `stat -c '%a' .env` prints `600`.
- `watchtower-db upgrade` ends without an error.
- Running it a second time changes nothing.

## Step 5: Subfinder

Subfinder finds subdomains from passive sources. Without it, scans find nothing beyond the root domain.

- Download the latest `subfinder_*_linux_amd64.zip` from https://github.com/projectdiscovery/subfinder/releases (on Apple silicon Macs, use `darwin_arm64`).
- **Verify its SHA-256 against the release's `checksums.txt` before using it.** Stop if it doesn't match.
- Put the binary in `.venv/bin/subfinder` with mode 700, or anywhere on `PATH`.

**Verify:** `.venv/bin/subfinder -version` prints a version.

## Step 6: start script and first start

Windows/WSL:

```bash
cp ~/.local/share/watchtower/app/deploy/windows/start.sh ~/.local/share/watchtower/start.sh
bash ~/.local/share/watchtower/start.sh status
```

`status` may say that no project exists yet; that is fine. Any database error is not.

Then the user double-clicks **`Start-Dashboard.cmd`** on Windows. Linux/macOS users run `python terminal_ui.py --dashboard --open-browser` with `.env` loaded and `.venv/bin` on `PATH`.

**Verify:**
- `curl -s http://127.0.0.1:8080/api/v1/health` returns `"status": "ok"`.
- The dashboard window prints *"Scan worker running"*.
- http://localhost:8080 opens the universe view **without a sign-in screen**, on the same machine.

This step needs the `development` profile. Its `auth.local_dashboard = true` setting is what lets the dashboard open without signing in.

Then hand over to the user: they add their first target with **+ Add target** (see ground rule 2).

## Step 7 (optional): local AI review

Only if the user wants it:

1. The user installs [Ollama](https://ollama.com) and pulls a model, such as `qwen3:8b-q4_K_M` (~5 GB). Ask before pulling: it is a large download.
2. Reaching Ollama from WSL: see [docs/ai-review.md](docs/ai-review.md#2-reaching-the-model-from-ubuntu-on-wsl). The simplest option is Ollama inside Ubuntu, with the default endpoint `http://127.0.0.1:11434`. If Ollama runs on Windows, use `http://windows-host:11434` plus `WATCHTOWER__AI__ALLOW_PRIVATE_ENDPOINT=true`, and the WSL-only firewall rule from that document. Never open the port to the whole network.
3. Append to `.env` (keeping mode 600):
   - `WATCHTOWER__AI__ENABLED=true`
   - `WATCHTOWER__AI__MODEL=<exact installed model name>`
   - and the endpoint lines, if needed
4. Restart the dashboard. Its window should print *"AI worker running"*.

**Verify:** after the user has added a target, **AI Review → Model status and Advanced** (or terminal `a` → `7`) shows **READY**.

## Step 8: tell the user how to use it

Finish with a short summary for the user:

- **Daily use:** `Start-Dashboard.cmd` (keep the window open; scans and AI reviews run in it) and `Start-WatchTower.cmd` for the terminal menu.
- **Adding a target:** + Add target, with their own authorization.
- **Partial scans:** a **partial** scan result is expected while detection rules await approval.
- **What was installed and where:** paths only, never secrets.
- **Anything you skipped or that failed.**

## Step 9: updating an existing install

1. Ask the user to close the dashboard and terminal windows.
2. `cd ~/.local/share/watchtower/app && git status`. If there are local changes, **stop and ask**; do not discard them.
3. `git pull`, then `.venv/bin/python -m pip install -e '.[api,workers]' -r requirements.txt`.
4. Load `.env` and run `.venv/bin/watchtower-db upgrade`. Suggest a PostgreSQL backup (`pg_dump`) first.
5. Copy `deploy/windows/start.sh` again on Windows, and restart the dashboard.

## Troubleshooting reference

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `password authentication failed` | `.env` does not match the role's password | Reset the role's password to a new generated value and update `.env`. Ask first. |
| `permission denied for schema public` | Schema ownership step skipped | Run the `ALTER SCHEMA public OWNER TO watchtower` step from Step 4 |
| `Port 8080 is occupied` | A dashboard is already running | Use it, or ask the user to close the other window |
| Dashboard shows a sign-in screen on the same PC | Profile is not `development`, or `--allow-remote` was used | Set `WATCHTOWER_PROFILE=development` in `.env`; start without `--allow-remote` |
| Scans stay **queued** | No worker running | The dashboard window must stay open; check that it printed *"Scan worker running"* |
| Scan finds only the root domain | Subfinder missing | Step 5 |
| `.cmd` window: distribution not found | Distribution name differs | `setx DEVILS_EYES_DISTRO "<name>"` and open a new window |
| AI: Refused by policy | Public endpoint, or private one without `ALLOW_PRIVATE_ENDPOINT` | Use loopback or the WSL host, as in Step 7 |
| AI: Unreachable | Ollama not running, or WSL cannot reach Windows | Start Ollama; see the WSL networking options in docs/ai-review.md |
| AI review returns no candidates | Only stored scan data was reviewed | The user should run **Collect scripts for review** after a scan finishes |

## Checks you can run safely

These send nothing to any target:

```bash
bash ~/.local/share/watchtower/start.sh status         # database and project summary
curl -s http://127.0.0.1:8080/api/v1/health            # dashboard server
.venv/bin/python -m watchtower.adapters.checks         # lists detection rules and their approval state
.venv/bin/python -m pytest -q tests/test_terminal_ui.py tests/api/test_dashboard_static.py   # unit tests; needs pip install -e '.[dev]'
```
