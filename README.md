# Devils Eyes (WatchTower)
<img width="1035" height="554" alt="image" src="https://github.com/user-attachments/assets/26764111-05c5-439a-b324-ef9a253f14f4" />

**Keep watch over your attack surface as it changes.**

Devils Eyes monitors the attack surface of domains you are **authorized** to test. It finds subdomains, keeps a DNS and HTTP inventory, compares every scan with the last one, alerts you about changes, and can ask a **local** AI model to review the pages and JavaScript it collected. Everything is stored in PostgreSQL and runs on your own machine.

You can use it in two ways, and they share the same data:

- **The dashboard:** a 3D "universe" in your browser. The Devils Eye sits in the centre and every target domain is a planet. When a scan finds something new, a pulse travels from the eye to that planet. Click a planet to see its name, and click again to fly into its page: assets, findings, changes, alerts, scan history and the AI review.
- **The terminal menu:** a guided menu for scans, progress, inventory, findings, continuous monitoring and the AI review.

The Python package and command-line tools are called `watchtower`.

```mermaid
flowchart LR
    A[You add an authorized target] --> B[Scan: discovery, DNS, HTTP, checks]
    B --> C[(PostgreSQL: inventory, findings, evidence)]
    B --> D[Alerts and dashboard pulses]
    C --> E[Dashboard / terminal / CLI / API]
    C --> F[Optional local AI review]
    E -->|retest| B
```

## Contents

- [What you need](#what-you-need)
- [Setup on Windows (WSL)](#setup-on-windows-wsl)
- [Setup on Linux or macOS](#setup-on-linux-or-macos)
- [Using Devils Eyes](#using-devils-eyes)
- [Optional: AI review with a local model](#optional-ai-review-with-a-local-model)
- [Setting it up with an AI assistant](#setting-it-up-with-an-ai-assistant)
- [Safety rules built in](#safety-rules-built-in)
- [Troubleshooting](#troubleshooting)
- [Documentation](#documentation)
- [Project layout](#project-layout)
- [Legacy discovery](#legacy-discovery)

## What you need

| Component | Version | Used for |
| --- | --- | --- |
| Python | 3.11 or newer | the application |
| PostgreSQL | 16 or 17 | all data |
| Git | any | getting the code |
| [Subfinder](https://github.com/projectdiscovery/subfinder) | latest release | finding subdomains from passive sources |
| [Ollama](https://ollama.com) with a model | optional | the AI review |
| Docker with Compose | optional | an alternative way to run PostgreSQL, and the [demo lab](lab/README.md) |

Supported systems: **Windows 10/11 through WSL2 (Ubuntu)**, **Linux** and **macOS**.

> **Just want to look first?** With only Docker installed, `lab/lab.sh demo` runs the whole journey against test targets on an isolated network. See [lab/README.md](lab/README.md).

## Setup on Windows (WSL)

On Windows, Devils Eyes runs inside Ubuntu on WSL2. You start it from Windows with the `.cmd` files in this repository.

### 1. Install Ubuntu on WSL

Open **PowerShell as Administrator**:

```powershell
wsl --install -d Ubuntu-24.04
```

Restart if asked, open **Ubuntu** from the Start menu, and create your Linux user name and password.

> The `.cmd` files use the distribution `Ubuntu-24.04`. If yours has another name (see `wsl -l -v`), set it once in PowerShell: `setx DEVILS_EYES_DISTRO "Ubuntu"`.

### 2. Install the system packages

Inside the **Ubuntu** terminal:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip postgresql unzip curl
sudo service postgresql start
```

### 3. Get the code

The Windows start files expect the app at `~/.local/share/watchtower/app`:

```bash
mkdir -p ~/.local/share/watchtower
git clone https://github.com/OmidRahmanian/Devil-Eyes.git ~/.local/share/watchtower/app
cd ~/.local/share/watchtower/app
```

### 4. Install the application

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[api,workers]' -r requirements.txt
```

### 5. Create the database

This creates a private database user with a random password and saves the connection in `.env`. `.env` is ignored by Git, so the password never reaches the repository.

```bash
PASS=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
sudo -u postgres psql -v ON_ERROR_STOP=1 -d postgres <<SQL
CREATE ROLE watchtower LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD '$PASS';
CREATE DATABASE watchtower OWNER watchtower;
REVOKE ALL ON DATABASE watchtower FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE watchtower TO watchtower;
SQL
sudo -u postgres psql -v ON_ERROR_STOP=1 -d watchtower -c 'REVOKE CREATE ON SCHEMA public FROM PUBLIC; ALTER SCHEMA public OWNER TO watchtower;'

umask 077
printf 'WATCHTOWER__DATABASE__URL=postgresql+psycopg://watchtower:%s@127.0.0.1:5432/watchtower\nWATCHTOWER_PROFILE=development\n' "$PASS" > .env
unset PASS

set -a; . ./.env; set +a
.venv/bin/watchtower-db upgrade
```

The application deliberately connects as a normal user, not a superuser. That keeps PostgreSQL's row-level security active, so each request only sees its own project.

### 6. Install Subfinder

Download the latest `subfinder_*_linux_amd64.zip` from the [Subfinder releases page](https://github.com/projectdiscovery/subfinder/releases), check it against the release's `checksums.txt`, and put the binary into the app's environment:

```bash
cd ~/.local/share/watchtower/app
unzip -o ~/subfinder_*_linux_amd64.zip subfinder -d .venv/bin/   # adjust the path to where you saved the zip
chmod 700 .venv/bin/subfinder
.venv/bin/subfinder -version
```

If you have Go installed, `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` also works, as long as `subfinder` ends up on your `PATH`.

### 7. Install the start script

```bash
cp ~/.local/share/watchtower/app/deploy/windows/start.sh ~/.local/share/watchtower/start.sh
bash ~/.local/share/watchtower/start.sh status
```

`status` should answer without errors. It is fine if it says that no project exists yet.

### 8. Start it from Windows

Clone or download this repository on Windows too, or copy just the three `.cmd` files somewhere handy, such as your Desktop:

| File | What it does |
| --- | --- |
| `Start-Dashboard.cmd` | Starts PostgreSQL, the dashboard, the scan worker and the AI worker, then opens http://localhost:8080. **Keep its window open:** scans and AI reviews run in it. |
| `Start-WatchTower.cmd` | Opens the terminal menu. |
| `Copy-Dashboard-Token.cmd` | Copies a sign-in token. Only needed to open the dashboard from **another** device. |

Double-click **`Start-Dashboard.cmd`**. The dashboard opens without signing in, and you can add your first target. See [Using Devils Eyes](#using-devils-eyes).

## Setup on Linux or macOS

```bash
git clone https://github.com/OmidRahmanian/Devil-Eyes.git
cd Devil-Eyes
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[api,workers]' -r requirements.txt
```

**PostgreSQL:** on Linux, install the `postgresql` package and run the same commands as in [Windows step 5](#5-create-the-database). On macOS, or if you prefer Docker, use the bundled container:

```bash
cp deploy/.env.example deploy/.env      # then replace every password in it
docker compose -f deploy/compose.yaml --env-file deploy/.env up -d postgres
umask 077
printf 'WATCHTOWER__DATABASE__URL=postgresql+psycopg://watchtower:<WATCHTOWER_DB_PASSWORD from deploy/.env>@127.0.0.1:5432/watchtower\nWATCHTOWER_PROFILE=development\n' > .env
```

Then apply the schema:

```bash
set -a; . ./.env; set +a
.venv/bin/watchtower-db upgrade
```

**Subfinder:** install it from its [releases page](https://github.com/projectdiscovery/subfinder/releases) (or `brew install subfinder` on macOS) so that `subfinder` is on your `PATH`.

**Start it:**

```bash
set -a; . ./.env; set +a
export PATH="$PWD/.venv/bin:$PATH"
python terminal_ui.py --dashboard --open-browser   # dashboard + scan and AI workers; keep it running
python launcher.py --platform                      # the terminal menu, in a second terminal
```

More detail, including roles, tokens, notifications and production deployment, is in [docs/installation.md](docs/installation.md).

## Using Devils Eyes

### Add a target (dashboard)

1. Open the dashboard (`Start-Dashboard.cmd`, or http://localhost:8080 while it runs).
2. Click **+ Add target**.
3. Enter a domain or website link, for example `example.com`.
4. Choose **A new project for this target** (its own planet), or add it to an existing project.
5. Tick **Also discover and scan all of its subdomains** if you want `*.example.com` too.
6. Fill in **who granted you permission** (a contract, bug bounty program, or your own ownership) and tick the confirmation box.
7. Leave **Start a scan now** ticked and click **Add target**.

A new planet forms. Its scan starts within a few seconds in the dashboard window, and the planet pulses as assets are found. You can add as many targets as you like.

Each scan works through **discovery** (subdomains, from passive sources), **dns**, **http** (which hosts serve websites) and **checks** (the vulnerability rules).

To **remove** a target, open its planet and use **Remove this target** at the bottom of its page. Removed targets are **archived**, never erased, because the history is kept on purpose.

### The terminal menu

Open it with `Start-WatchTower.cmd`, or with `python launcher.py --platform`.

| Key | Menu item |
| --- | --- |
| `1` | **Start scan:** scan once, or set up **continuous monitoring** on a schedule |
| `2` | **View scan progress:** watch, resume or cancel a run |
| `3` / `4` | Browse inventory / findings |
| `5` | Advanced target settings (scope) |
| `6` | Alerts |
| `7` | Open the dashboard |
| `8` | Switch project |
| `a` | AI security review |

The terminal works on one project at a time. Press `8` to choose which one.

### The dashboard on other devices

On the computer that runs it, the dashboard opens without signing in. Requests from other devices, and from other websites in your browser, are refused. To use it from another device, start the server with `watchtower serve --host 0.0.0.0 --allow-remote` behind TLS, and sign in with a token (`Copy-Dashboard-Token.cmd`). See [docs/installation.md](docs/installation.md#6-dashboard-and-api).

## Optional: AI review with a local model

The AI review is **off by default** and never uses an online AI service. It reads what Devils Eyes collected for a target (pages, headers, in-scope JavaScript) and asks a model running on **your** machine for possible security issues. Every suggestion has to quote the exact code it is based on, and the quotes are verified. Suggestions never become findings on their own.

1. Install [Ollama](https://ollama.com) and a model, for example `ollama pull qwen3:8b-q4_K_M` (about 5 GB; fits an 8 GB GPU).
2. Make the model reachable from Devils Eyes. On Windows with WSL, see [the networking options](docs/ai-review.md#2-reaching-the-model-from-ubuntu-on-wsl).
3. Turn it on in `.env`:

   ```bash
   WATCHTOWER__AI__ENABLED=true
   WATCHTOWER__AI__MODEL=qwen3:8b-q4_K_M
   # Only when Ollama runs on the Windows host rather than inside Ubuntu:
   WATCHTOWER__AI__ENDPOINT=http://windows-host:11434
   WATCHTOWER__AI__ALLOW_PRIVATE_ENDPOINT=true
   ```

4. Restart the dashboard. Its window then says *"AI worker running"*.
5. Once you have added a target, check the connection on the dashboard's **AI Review → Model status and Advanced** page, or in the terminal under **`a` → `7` Model status**. It should say **READY**.

To use it, open the dashboard's **AI Review** page, or the terminal's **`a`** menu:

- **Collect scripts for review:** downloads the in-scope pages and scripts, then reviews them. This is the useful one.
- **Review latest scan:** reviews only what the scan stored (URLs, titles, a few headers), so it often finds nothing.

Full details are in [docs/ai-review.md](docs/ai-review.md).

## Setting it up with an AI assistant

If you would rather have an AI coding assistant do the setup, point it at **[AI-SETUP.md](AI-SETUP.md)**. That file is a step-by-step guideline written for an assistant: the order of the steps, how to verify each one, and what it must ask you before doing.

## Safety rules built in

- **Nothing is scanned without an authorized scope.** Adding a target records who authorized it, and every request is checked against that scope first.
- **Loopback, link-local, cloud metadata and reserved addresses are always refused.** Private networks are refused unless a profile explicitly allows them.
- **The vulnerability rules ship switched off.** The five detection rules in `rules/` only run after a maintainer approves them by pinning their hashes ([rules/README.md](rules/README.md)). Until then, scans still map subdomains, DNS and websites, but finish as **partial** and report no findings.
- **A finding is only resolved by a conclusive negative retest.** Failed or partial scans never count as a fix.
- **Secrets stay local.** Database passwords, tokens and webhook URLs live in `.env` or private files (mode 600), which Git ignores.
- **History is kept.** Projects and targets are archived, not deleted.

Only scan systems you own or have written permission to test. For bug bounty programs, follow each program's rules on automated scanning and rate limits.

## Troubleshooting

| Problem | What to do |
| --- | --- |
| The dashboard shows an old page | Press **Ctrl+Shift+R** to reload without the cache. |
| A scan stays **queued** | The dashboard window must be open, because it runs the scans. Or run one from the terminal: `2` (View scan progress), then `3` (Open processing window). |
| `Port 8080 is occupied` | A dashboard is already running. Use it, or close the other window first. |
| `could not connect to server` / database errors | Start PostgreSQL: `sudo service postgresql start`. `Start-*.cmd` does this for you. |
| Scans finish as **partial** | Expected while the detection rules await approval. See [Safety rules built in](#safety-rules-built-in). |
| The AI review says **Unreachable** or **Model missing** | Start Ollama, then look at **Model status**. See [docs/ai-review.md](docs/ai-review.md#troubleshooting-connection-check). |
| The AI review finds nothing | Use **Collect scripts for review** after the scan has finished. A plain review only sees URLs and titles. |
| WSL distribution not found | `setx DEVILS_EYES_DISTRO "<name from wsl -l -v>"`, then open a new window. |

## Documentation

| Topic | Document |
| --- | --- |
| Full installation, roles, tokens, notifications | [docs/installation.md](docs/installation.md) |
| Terminal menu | [docs/terminal.md](docs/terminal.md) |
| AI review | [docs/ai-review.md](docs/ai-review.md) |
| HTTP API | [docs/api.md](docs/api.md) |
| Investigation, feeds, exports, request limits, retention | [docs/operations.md](docs/operations.md) |
| What a scan covers, and what it does not | [docs/coverage.md](docs/coverage.md) |
| Architecture and threat model | [docs/architecture.md](docs/architecture.md), [docs/threat-model.md](docs/threat-model.md) |
| Reporting a vulnerability | [SECURITY.md](SECURITY.md) |
| Setup guideline for AI assistants | [AI-SETUP.md](AI-SETUP.md) |
| Licence | [MIT](LICENSE); dependencies keep [their own licences](THIRD_PARTY_NOTICES.md) |

### Command line

Everything the menus do is also available from the `watchtower` CLI:

```bash
watchtower scope publish --include example.com --include '*.example.com' \
  --authorization-kind contract --reference SOW-14 --granted-by "Example CISO" --i-am-authorized
watchtower run start --watch --work
watchtower findings
watchtower finding retest <id> --watch --work
watchtower serve                     # dashboard at http://127.0.0.1:8080
```

### Running the tests

```bash
.venv/bin/python -m pip install -e '.[dev]' -r requirements.txt
docker run -d --name wt-test-pg -e POSTGRES_PASSWORD=postgres -p 127.0.0.1:55432:5432 postgres:17-alpine
WATCHTOWER_TEST_DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:55432/postgres .venv/bin/python -m pytest
```

Without `WATCHTOWER_TEST_DATABASE_URL`, the database tests are skipped.

## Project layout

| Path | Role |
| --- | --- |
| `src/watchtower/` | The application: domain, persistence, services, workers, API (`api/`) and CLI (`cli.py`) |
| `frontend/` | The dashboard. Plain JavaScript with no build step; `frontend/universe/` is the 3D view, and `frontend/vendor/` holds the pinned Three.js |
| `terminal_ui.py`, `launcher.py` | The terminal menu and the launcher that opens it |
| `Start-*.cmd`, `Copy-Dashboard-Token.cmd`, `deploy/windows/` | The Windows start files and their WSL helper scripts |
| `config/profiles/` | Settings profiles (`development`, `production`, `lab`, `test`) |
| `migrations/` | Database schema migrations (`watchtower-db upgrade`) |
| `rules/` | Detection rules and their maintainer-approved manifest |
| `deploy/` | Docker Compose files for PostgreSQL and workers |
| `lab/` | The isolated demonstration lab |
| `docs/` | Documentation |
| `tests/` | Automated tests |
| `watch.py`, `start.py`, `manager.py`, `*.json` | The legacy MongoDB toolkit (below) |

## Legacy discovery

The rest of this README describes the original MongoDB toolkit. It is separate from everything above and still works on its own. New users do not need it.

### What it does

- **Discover subdomains** with Subfinder, certificate transparency data from crt.sh, and SecurityTrails.
- **Resolve discovered names** with ShuffleDNS and wordlists, including integrations for DNSGen, Altdns, and AlterX.
- **Track HTTP services** and compare status codes, page titles, detected technologies, and response body hashes.
- **Run Nuclei checks** against newly discovered assets and integrate new template checks.
- **Send notifications** for discoveries, HTTP changes, scan results, and runtime errors.
- **Explore your inventory** through a terminal manager with searches, exports, target management, and settings.

```mermaid
flowchart LR
    A[Target domains] --> B[Subdomain discovery]
    B --> C[DNS resolution]
    C --> D[HTTP service checks]
    D --> E[Nuclei checks]
    B --> F[(MongoDB inventory)]
    C --> F
    D --> F
    B --> G[Discord / Telegram]
    D --> G
    E --> G
    F --> H[Terminal manager / exports]
```

### Interactive setup

Start the guided terminal interface:

```bash
python3 launcher.py
```

The launcher opens with a WatchTower ASCII eye banner, with a red pupil in colour terminals and a compact version for narrow windows. Preview it with `python3 launcher.py --banner`. Set `NO_COLOR=1` for plain text.

The launcher first asks which mode to use. **Platform** (`python3 launcher.py --platform`) opens a persistent home menu for scans, progress, inventory, findings, scope, alerts and the dashboard. Select an accessible project by number or create one; your project, profile and token-file path are remembered. **Start scan** queues one run and opens a separate terminal window for its worker and progress, leaving Home available. See the [terminal guide](docs/terminal.md). **Legacy discovery** (`python3 launcher.py --legacy`) is the setup described below.

The launcher uses the project's virtual environment when one is available. Choose a saved target or enter a domain, add an optional report URL and exact subdomain exclusions, and select a discovery schedule:

- **Quick discovery test:** Subfinder every minute.
- **Recurring discovery:** Subfinder every three hours.
- **Custom interval:** Choose a number of minutes, hours, or days.

Choose whether to send Discord notifications. If credentials are missing, the launcher asks for one webhook without displaying it and saves it in the ignored `.env` file. Telegram credentials are optional.

Select **Save and start** to write `targets.json` and `setting.json`, start MongoDB through Docker Compose, and run WatchTower with live terminal output and an appended `files/watchtower.log`. The first discovery runs after the interval you selected. Press **Ctrl+C** to stop monitoring.

This setup selects one target and disables other discovery jobs and Nuclei scans. Each saved setup creates a backup of the previous configuration in `files/config-backups/`. If another session is running, the launcher offers to stop it before saving. You can also choose **Save setup only** or **Cancel**.

Docker and Subfinder must already be installed. Install Python dependencies once with `.venv/bin/python -m pip install -r requirements.txt` after creating the virtual environment described below. The launcher supports macOS and Linux.

### Requirements

WatchTower uses Python, MongoDB, and external command-line tools. Install the tools needed by the jobs you enable and make sure they are available on your `PATH`.

| Component | Purpose |
| --- | --- |
| Python 3.10+ recommended | Runs the scheduler and terminal manager |
| MongoDB at `mongodb://localhost:27017/` | Stores discovered assets and service metadata |
| Docker with Compose | Runs MongoDB using the included configuration |
| Subfinder | Subdomain discovery |
| PostgreSQL client (`psql`) | crt.sh certificate transparency queries |
| ShuffleDNS and MassDNS | DNS resolution and wordlist checks |
| ProjectDiscovery httpx | HTTP probing; this is the ProjectDiscovery CLI |
| Nuclei and Git | Scanning and template retrieval |
| DNSGen, Altdns, AlterX | Dynamic subdomain permutations |

SecurityTrails also requires an API key. DNS jobs require a resolver list at `~/.resolvers`, a static wordlist at `wordlist/static.txt`, and, for dynamic resolution, a permutation wordlist at `wordlist/gen_alt.txt`. Supply these files before enabling the corresponding jobs.

### Manual setup

#### 1. Install Python dependencies

```bash
git clone https://github.com/OmidRahmanian/Devil-Eyes.git
cd Devil-Eyes
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
mkdir -p files export output wordlist
```

#### 2. Start MongoDB

```bash
docker compose up -d mongodb
```

If your installation provides the standalone Compose command, use `docker-compose up -d mongodb`.

#### 3. Configure notifications

For manual setup, create a local `.env` file with your credentials. `./run.sh` loads it automatically; load it into your shell before running the Python backend directly.

One Discord webhook can serve every notification category. Separate webhooks can route categories to different channels.

```bash
DISCORD_WEBHOOK_URL='https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN'
NEW_SUB_WEBHOOK_URL="$DISCORD_WEBHOOK_URL"
NEW_RES_WEBHOOK_URL="$DISCORD_WEBHOOK_URL"
HTTP_CHANGE_WEBHOOK_URL="$DISCORD_WEBHOOK_URL"
NEW_HTTP_WEBHOOK_URL="$DISCORD_WEBHOOK_URL"
NUCLEI_WEBHOOK_URL="$DISCORD_WEBHOOK_URL"
OTHER_WEBHOOK_URL="$DISCORD_WEBHOOK_URL"

TELEGRAM_CHAT_ID='YOUR_CHAT_ID'
TELEGRAM_BOT_TOKEN='YOUR_BOT_TOKEN'
NEW_SUB_TELEGRAM_TOKEN="$TELEGRAM_BOT_TOKEN"
NEW_RES_TELEGRAM_TOKEN="$TELEGRAM_BOT_TOKEN"
HTTP_CHANGE_TELEGRAM_TOKEN="$TELEGRAM_BOT_TOKEN"
NEW_HTTP_TELEGRAM_TOKEN="$TELEGRAM_BOT_TOKEN"
NUCLEI_TELEGRAM_TOKEN="$TELEGRAM_BOT_TOKEN"
OTHER_TELEGRAM_TOKEN="$TELEGRAM_BOT_TOKEN"

# Required when using SecurityTrails; multiple keys are comma-separated.
SECURITYTRAILS_API_KEYS='YOUR_SECURITYTRAILS_API_KEY'
```

`watch.py` requires the six Discord variables when `sendmessage` is enabled. Disabling that setting turns off notifications and allows discovery without webhook credentials. Telegram is optional: configure its chat ID and the tokens for the categories you want to receive. The same Telegram bot token can serve each category. `start.py` requires its Discord variables independently of the notification switch.

Load the configuration:

```bash
chmod 600 .env
set -a
source .env
set +a
```

`.env` is ignored by Git. Keep real webhook URLs, bot tokens, and API keys in that local file.

#### 4. Set your targets

Replace the sample domains in `targets.json` with your own scope:

```json
{
  "example.com": {
    "report_url": "https://example.com/security",
    "out_of_scope": [
      "excluded.example.com"
    ]
  }
}
```

`targets.json` drives recurring monitoring. `starttargets.json` supplies domains for the separate initial collection script. The `out_of_scope` checks compare exact subdomain strings; they do not expand wildcard patterns.

#### 5. Choose your jobs

Edit `setting.json` to enable integrations you have configured. Each recurring job has a `status`, a numeric `value`, and a `time` unit such as `hours`, `days`, or `weeks`:

```json
"subfinder": {
  "time": "hours",
  "value": "3",
  "status": "enable"
}
```

This is an entry inside the settings object. Use `"status": "disable"` for jobs with missing tools or credentials.

The sample intervals schedule Subfinder, crt.sh, and SecurityTrails every three hours; DNS resolution every six hours; static wordlist resolution every three days; dynamic resolution weekly; and HTTP checks and new template checks daily. Each job also needs its status set to `enable` to run. The interactive discovery setup replaces these with your chosen Subfinder interval and disables the other jobs.

Additional settings control notifications, HTTP change comparisons, scanning new assets, and the Nuclei command arguments.

#### 6. Run WatchTower

From the project directory, with the virtual environment active and credentials loaded:

```bash
python -u watch.py
```

The scheduler waits until each job's first interval has elapsed. Starting it does not immediately run a full scan. Keep the process running to execute scheduled jobs.

For an initial collection, configure `starttargets.json` and run:

```bash
python -u start.py
```

`start.py` runs its collection pipeline immediately, including SecurityTrails, and requires that pipeline's dependencies and API key. After a successful run, it merges those targets into `targets.json`.

### Manage findings

Open the terminal manager in another shell:

```bash
source .venv/bin/activate
python manager.py
```

The menu supports exporting discovered, resolved, and HTTP assets; searching by subdomain, status code, technology, or title; querying records; editing targets; and updating settings. Exports are written to `export/`.

### Legacy operational notes

WatchTower is an early version that coordinates external tools. Check each enabled integration with your installed tool versions before relying on unattended monitoring.

- A startup error naming a missing webhook means Discord is enabled without complete credentials. Run `python3 launcher.py` to configure it or choose discovery without notifications.
- MongoDB must be reachable at `localhost:27017` before collection or inventory queries run.
- `SECURITYTRAILS_API_KEYS is not configured` means the SecurityTrails job needs credentials or should be disabled in the recurring scheduler.
- `./run.sh` starts the backend with the saved setup and credentials. Use the interactive launcher when you also want MongoDB started automatically.
- Run commands from the repository directory because the scripts use relative paths for settings and working files.

Use WatchTower within the scope of systems you own or are authorized to assess.

