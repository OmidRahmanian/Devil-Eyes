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

The banner animates once, then stays at the top of the terminal with the
project, database, scope and latest-run status beneath it. Each menu choice
replaces the screen below that header in place, so earlier menus do not pile up
in the scrollback; messages and errors appear above the current menu, and scan
progress refreshes in the same spot. Short terminals switch to a one-line
header. Piped output, `TERM=dumb` and `python launcher.py --platform --no-clear`
print screens one after another instead.

Choose an accessible project by number. Use
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
| Start scan | **Scan once**: add a domain or website link, confirm permissions and start, or scan a saved target again. **Continuous monitoring**: scan a target now and repeat it on a schedule |
| View scan progress | Selects an existing run; inspect, watch, open/resume a processing window, or explicitly cancel |
| Browse inventory | Lists assets, optionally filtered by search text |
| Browse findings | Lists findings; inspect details, triage or queue a retest |
| Advanced target settings | Edit scope, exclusions and authorization; inspect history or revoke permission |
| View alerts | Shows notification history and delivery status |
| Open dashboard | Reuses a running local server or opens a server window, then opens the browser |
| Switch saved targets / projects | Offers numbered accessible projects and token-file selection; also available inside Start scan |
| Settings and help | Changes profile or explains credentials, legacy mode and noninteractive commands |
| a) AI security review | Optional, local-only review of collected scripts and scan evidence, with feedback and project memory. Off by default; see [ai-review.md](ai-review.md) |

Browse findings > Inspect finding also offers **Explain this finding**, which
starts an AI review of that finding's stored evidence after the same preview.

**0** returns from menus; **b** returns from text fields. Enter accepts the shown
default. Ctrl+C returns to Home during an action, or stops a progress viewer.
End-of-input exits cleanly. Output wraps for narrow terminals and respects
`NO_COLOR`. Captured content is printed as escaped text, never interpreted as
terminal commands.

## Add a target and scan

Choose **1 — Start scan**, then **Scan once** for a single scan or
**Continuous monitoring** for repeated scans (see below). With no saved target,
setup opens immediately:
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
All choices in Start scan use numbers. If a scan is already queued or running,
Start scan offers **Continue** for that saved run, **Add a new target**, and
**Choose another saved target**. Continue opens the processing/progress window
for the same run rather than queueing a duplicate. A queued run waiting for a
worker can therefore be started directly from option 1. Adding another target
keeps the unfinished scan and its original target settings intact.

On WSL, Windows opens a separate terminal for scan progress, leaving Home
available. On macOS and other Linux installations a separate terminal is also
used. If opening a window fails, Retry and Process in this terminal remain
available for the same run. No scan
starts without confirmed scope, and pending detection rules remain disabled.

The header reports connection/access status, scope and the latest run, plus a
Monitoring line while continuous monitoring is set up. It refreshes when Home
is redisplayed; Home itself is not a background monitor. The scope menu
does not add wildcard coverage unless you explicitly choose it and confirm
authorization. Platform scope lives in PostgreSQL. Legacy `targets.json` and
`setting.json` remain separate and unchanged by platform menus.

## Continuous monitoring

Choose **1 — Start scan > Continuous monitoring** to scan a target now and then
again at a fixed interval, without running a scheduler and a worker yourself.

1. Pick a saved target, **Add a new target** (the same setup and permission
   confirmation as Scan once), or **Choose another saved target**.
2. Choose what to monitor. **Only the selected target** is the default.
   **All authorized projects** lists every project you can operate together with
   its targets, and needs a separate confirmation. These whole-project watches
   follow each project's current published scope.
3. Choose an interval: 1, 3, 6 (default), 12 or 24 hours, or a custom value
   such as `90m`, `8h` or `2d` (15 minutes to 30 days).
4. Review the summary and confirm. A separate monitoring window opens (a new
   Windows console on WSL), and Home stays available.

The monitoring window runs a worker and starts the first scan immediately. It
then starts the next scan one interval after the previous one started. Every
scan goes through the same path as Scan once, so saved permissions, exclusions,
request limits and pending detection-rule approvals apply unchanged. Inventory,
change comparisons, findings and alerts appear in the dashboard and terminal
views as for any other scan.

**Monitoring only runs while the computer is awake and the monitoring window
stays open.** Sleep, shutdown or closing the window pauses it. Missed intervals
are not replayed: when monitoring resumes, one scan starts if one is due.

Choose **Continuous monitoring** again to see the status: active, paused or not
running, the interval, and for each target the current scan and phase, the last
finished scan, and the next scheduled scan. The controls are:

| Control | Effect |
| --- | --- |
| View current scan progress | Follows the running monitored scan; Ctrl+C stops only the viewer |
| Pause monitoring | No new scans start; a running scan finishes |
| Resume monitoring | Scheduling continues; if the window was closed, it reopens |
| Change interval | Applies from the start of the last scan |
| Stop monitoring (keep any running scan) | Ends monitoring; **a running scan is not cancelled** and can be resumed from View scan progress |
| Stop monitoring and cancel running scans | Ends monitoring and cancels running scans of the monitored targets only; findings are not resolved |

Duplicates and overlaps are prevented in several ways:

- Only one monitoring window runs per profile, enforced by a lock. A second
  window refuses to start.
- A target is never scanned twice at once. If a scan of it is still running,
  including one started with Scan once, the next scan waits until it finishes.
- Each scheduled scan has a fixed request key until its start is saved. After a
  crash or restart, the same scan is returned instead of a second one being
  queued.

If a scan cannot start, for example because the database is unreachable or the
scope changed, the window shows the problem and retries on its next check. If
the worker itself stops, the window explains the cause and exits; resume it
from Home. Closing the window, Ctrl+C, a crash or a restart never cancels a
scan. Home then shows `Monitoring: NOT RUNNING`, and nothing restarts
automatically until you choose **Resume monitoring**.

The plan and its progress are stored under the ignored
`files/terminal-ui/monitors/` directory, with token-file paths only. Like scan
windows, the monitoring worker may also process due jobs and notifications from
other projects.

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
