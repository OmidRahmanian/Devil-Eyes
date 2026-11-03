# Terminal home

Activate the installed Python environment and open the launcher:

```bash
source .venv/bin/activate
python launcher.py --platform
```

The banner defaults to twice its original speed (about 2–3 seconds). In your
Ubuntu terminal, adjust the speed multiplier for one launch:

```bash
DEVILS_EYES_BANNER_SPEED=4 python launcher.py --platform  # faster
DEVILS_EYES_BANNER_SPEED=1 python launcher.py --platform  # original slow reveal
DEVILS_EYES_BANNER_SPEED=0 python launcher.py --platform  # instant
```

Use `export DEVILS_EYES_BANNER_SPEED=4` to keep that pace for the current
terminal session. Reduced-motion and no-animation settings still take priority.

The large banner appears once. Choose an accessible project by number. Use
**Create project** for a new project, **Use another token file** for existing
credentials, or **Change profile** for Development, Lab or Production. Creating
a project needs the configured database access; it does not publish scope or
start scanning. New projects receive separate token files, preserving older
tokens. Revoked or inaccessible remembered projects return to project selection.

Home remembers your project, profile and token-file paths under the ignored
`files/terminal-ui/preferences.json` (mode 600). It stores no token contents or
database credentials. New tokens are stored privately under
`files/terminal-ui/tokens/`; your original token is retained. Keep this directory
private and backed up if you need these credentials later.

## Home actions

| Action | Behavior |
| --- | --- |
| Start scan | Add a domain or website link, confirm permissions and start; or pick a saved target to scan again |
| View scan progress | Selects an existing run; inspect, watch, open/resume a processing window, or explicitly cancel |
| Browse inventory | Lists assets, optionally filtered by search text |
| Browse findings | Lists findings; inspect details, triage or queue a retest |
| Advanced target settings | Edit scope, exclusions and authorization; inspect history or revoke permission |
| View alerts | Shows notification history and delivery status |
| Open dashboard | Reuses a running local server or opens a server window, then opens the browser |
| Switch saved targets / projects | Offers numbered accessible projects and token-file selection; also available inside Start scan |
| Settings and help | Changes profile or explains credentials, legacy mode and noninteractive commands |

**0** returns from menus; **b** returns from text fields. Enter accepts the shown
default. Ctrl+C returns to Home during an action, or stops a progress viewer.
End-of-input exits cleanly. Output wraps for narrow terminals and respects
`NO_COLOR`. Captured content is printed as escaped text, never interpreted as
terminal commands.

## Add a target and scan

Choose **1 — Start scan**. With no saved target, setup opens immediately:
paste a domain or website link, choose whether permission covers all subdomains,
enter any exclusions, and confirm your permission to scan. Website links use
their hostname; a page URL does not restrict scanning to that path, and a
`www` hostname is not silently expanded to its parent domain.

For assets you own, enter your name. For other permission types, supply the
program link, contract or approval reference and the organization granting it.
The final confirmation saves the target and starts one scan. Back or declining
before confirmation saves nothing. Later visits offer saved domains, **Add a
new target**, and **Choose another saved target / project** in the same flow.
New targets added alongside an existing scope get a separate project and token
automatically, preserving the previous target's scope, exclusions and history.
Saved scans reuse their existing authorization and scan only the selected root.

On WSL, Windows opens a separate terminal for scan progress, leaving Home
available. On macOS and other Linux installations a separate terminal is also
used. If opening a window fails, Retry and Process in this terminal remain
available for the same run. No scan
starts without confirmed scope, and pending detection rules remain disabled.

The header reports connection/access status, scope and the latest run. It refreshes
when Home is redisplayed; it is not a live background monitor. The scope menu
does not add wildcard coverage unless you explicitly choose it and confirm
authorization. Platform scope lives in PostgreSQL. Legacy `targets.json` and
`setting.json` remain separate and unchanged by platform menus.

## Separate scan window

On macOS, WatchTower uses Terminal.app; macOS may request permission for terminal
automation. On Linux it detects GNOME Terminal, Konsole, Xfce Terminal or xterm.
On Windows/WSL, PowerShell launches a new Windows console running the same WSL
distribution and the checkout's Python. Arguments contain only paths and
identifiers; the child privately loads its own environment and installed tools.
If no window can be opened, choose **Retry**, **Process in this terminal**, or
**Back**. All choices retain the same run ID; they do not queue another scan.
If the OS accepts a launch but the window fails afterward, use **View scan
progress > Open processing window / resume** to retry that existing run.

Keep credentials in the root `.env` as described in [installation.md](installation.md).
New windows load that file privately. Shell-only secrets are not copied into
launch commands or temporary scripts. Commands use the checkout's absolute
virtual-environment interpreter and working directory.

The progress window shows real run/job states, current phase, elapsed time,
available snapshot counts, errors and checks that did not run. Discovery,
DNS, HTTP, Checks and Finalize are shown without invented percentages.
Partial and failed outcomes remain distinct from success. Pending detection
rules stay disabled and cannot generate findings.

The in-window worker uses the existing shared queue: **it may also process due
jobs and notifications from other projects**. It is not a project-exclusive
worker. Two processing windows for the same run in this checkout are prevented
by a local lock. Home also checks for an active run before queueing another;
this is a convenience guard for this launcher, not global idempotency across
independent API clients or other checkouts.

Ctrl+C, closing the window, or stopping local processing **does not cancel the
run**. The local worker is asked to stop and requeue in-flight work; another
worker can resume it, and leases recover an abruptly killed process. Use
**View scan progress > Cancel run** to request actual cancellation. Stopping a
viewer without a worker only stops viewing. Final results remain visible until
you press Enter to close the scan window.

A retest queued from Findings also needs processing: select it under View scan
progress and open its processing window, or use your background workers.

## Dashboard and direct commands

Opening the dashboard leaves Home usable. Sign in using the token file shown
in the terminal. On macOS, copy it privately with `pbcopy < /path/to/token`.
The dashboard window owns its server; Ctrl+C there stops that server. To start
it manually from another terminal in the checkout:

```bash
.venv/bin/python terminal_ui.py --dashboard
```

The existing noninteractive CLI remains available, including machine-readable
project listing and run creation:

```bash
watchtower projects --json
watchtower --project acme status
watchtower --project acme run start --json
watchtower --project acme run show <run-id>
watchtower --project acme watch --run <run-id> --work
```

Direct CLI commands require the database environment to be loaded; the launcher
and `terminal_ui.py` load `.env` automatically. The JSON start command queues a
run; it does not process it. Use the existing worker or the terminal progress
window for processing. The web dashboard, API and scan engine are unchanged.
